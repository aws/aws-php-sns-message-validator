<?php

namespace Aws\Sns;

/**
 * @covers \Aws\Sns\MessageValidator
 */
class MessageValidatorTest extends \PHPUnit_Framework_TestCase
{
    const VALID_CERT_URL = "https://sns.foo.amazonaws.com/bar.pem";

    protected function setUp()
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('The OpenSSL extension is required to run '
                . 'the tests for MessageValidator.');
        }
    }

    public function testIsValidReturnsFalseOnFailedValidation()
    {
        $validator = new MessageValidator();
        $message = new Message([]);
        $this->assertFalse($validator->isValid($message));
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage The certificate is located on an invalid domain.
     */
    public function testValidateFailsWhenCertUrlInvalid()
    {
        $validator = new MessageValidator();
        $message = new Message([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar'
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\MessageValidatorException
     * @expectedExceptionMessage Cannot get the public key from the certificate.
     */
    public function testValidateFailsWhenCannotDeterminePublicKey()
    {
        $validator = new MessageValidator($this->getMockClient(''));
        $message = new Message([
            'SigningCertURL' => self::VALID_CERT_URL
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
        list($signature, $certificate) = $this->getSignature('foo');
        // Create the validator with a mock HTTP client that will respond with
        // the certificate
        $validator = new MessageValidator($this->getMockClient($certificate));
        $message = new Message([
            'SigningCertURL' => self::VALID_CERT_URL,
            'Signature'      => $signature,
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
        ]);

        // Get the signature for a real message
        list($signature, $certificate) = $this->getSignature($message->getStringToSign());
        $ref = new \ReflectionProperty($message, 'data');
        $ref->setAccessible(true);
        $ref->setValue($message, ['Signature' => $signature] + $ref->getValue($message));

        // Create the validator with a mock HTTP client that will respond with
        // the certificate
        $validator = new MessageValidator($this->getMockClient($certificate));

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    protected function getMockClient($responseBody)
    {
        return static function () use ($responseBody) {
            return $responseBody;
        };
    }

    protected function getSignature($stringToSign)
    {
        // Generate a new Certificate Signing Request and public/private keypair
        $csr = openssl_csr_new(array(), $keypair);
        // Create the self-signed certificate
        $x509 = openssl_csr_sign($csr, null, $keypair, 1);
        openssl_x509_export($x509, $certificate);
        // Create the signature
        $privateKey = openssl_get_privatekey($keypair);
        openssl_sign($stringToSign, $signature, $privateKey);
        // Free the openssl resources used
        openssl_pkey_free($keypair);
        openssl_x509_free($x509);

        return [base64_encode($signature), $certificate];
    }
}
