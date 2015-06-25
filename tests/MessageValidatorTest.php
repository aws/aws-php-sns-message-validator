<?php

namespace Aws\Sns;

/**
 * @covers MessageValidator
 */
class MessageValidatorTest extends \PHPUnit_Framework_TestCase
{
    const VALID_CERT_URL = "https://sns.foo.amazonaws.com/bar.pem";

    private static $pKey;

    private static $certificate;

    public static function setUpBeforeClass()
    {
        self::$pKey = openssl_pkey_new();
        $csr = openssl_csr_new([], self::$pKey);
        $x509 = openssl_csr_sign($csr, null, self::$pKey, 1);

        openssl_x509_export($x509, self::$certificate);
        openssl_x509_free($x509);
    }

    public static function tearDownAfterClass()
    {
        openssl_pkey_free(self::$pKey);
    }

    public function testIsValidReturnsFalseOnFailedValidation()
    {
        $validator = new MessageValidator();
        $message = new Message([]);
        $this->assertFalse($validator->isValid($message));
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage Only v1 signatures can be validated; v2 provided
     */
    public function testValidateFailsWhenSignatureVersionIsInvalid()
    {
        $validator = new MessageValidator();
        $message = new Message([
            'SignatureVersion' => '2',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage The certificate is located on an invalid domain.
     */
    public function testValidateFailsWhenCertUrlInvalid()
    {
        $validator = new MessageValidator();
        $message = new Message([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar',
            'SignatureVersion' => '1',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage Cannot get the public key from the certificate.
     */
    public function testValidateFailsWhenCannotDeterminePublicKey()
    {
        $validator = new MessageValidator($this->getMockHttpClient(''));
        $message = new Message([
            'SigningCertURL' => self::VALID_CERT_URL,
            'SignatureVersion' => '1',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage The message signature is invalid.
     */
    public function testValidateFailsWhenMessageIsInvalid()
    {
        // Get the signature for some dummy data
        $signature = $this->getSignature('foo');
        // Create the validator with a mock HTTP client that will respond with
        // the certificate
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = new Message([
            'SigningCertURL' => self::VALID_CERT_URL,
            'Signature'      => $signature,
            'SignatureVersion' => '1',
        ]);
        $validator->validate($message);
    }

    public function testValidateSucceedsWhenMessageIsValid()
    {
        // Create a real message
        $message = Message::fromArray([
            'Message'        => 'foo',
            'MessageId'      => 'bar',
            'Timestamp'      => time(),
            'TopicArn'       => 'baz',
            'Type'           => 'Notification',
            'SigningCertURL' => self::VALID_CERT_URL,
            'Signature'      => ' ',
            'SignatureVersion' => '1',
        ]);

        // Get the signature for a real message
        $signature = $this->getSignature($message->getStringToSign());
        $ref = new \ReflectionProperty($message, 'data');
        $ref->setAccessible(true);
        $ref->setValue(
            $message,
            ['Signature' => $signature] + $ref->getValue($message)
        );

        // Create the validator with a mock HTTP client that will respond with
        // the certificate
        $validator = new MessageValidator($this->getMockCertServerClient());

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    protected function getMockHttpClient($responseBody)
    {
        return function () use ($responseBody) {
            return $responseBody;
        };
    }

    protected function getMockCertServerClient()
    {
        return function ($url) {
            if ($url !== self::VALID_CERT_URL) {
                return '';
            }

            return self::$certificate;
        };
    }

    protected function getSignature($stringToSign)
    {
        openssl_sign($stringToSign, $signature, self::$pKey);

        return base64_encode($signature);
    }
}
