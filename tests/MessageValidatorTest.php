<?php
namespace Aws\Sns;

/**
 * @covers MessageValidator
 */
class MessageValidatorTest extends \PHPUnit_Framework_TestCase
{
    const VALID_CERT_URL = 'https://sns.foo.amazonaws.com/bar.pem';

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
        $message = $this->getTestMessage([
            'SignatureVersion' => '2',
        ]);
        $this->assertFalse($validator->isValid($message));
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage Only v1 signatures can be validated; v2 provided
     */
    public function testValidateFailsWhenSignatureVersionIsInvalid()
    {
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SignatureVersion' => '2',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The certificate is located on an invalid domain.
     */
    public function testValidateFailsWhenCertUrlInvalid()
    {
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar',
        ]);
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage Cannot get the public key from the certificate.
     */
    public function testValidateFailsWhenCannotDeterminePublicKey()
    {
        $validator = new MessageValidator($this->getMockHttpClient());
        $message = $this->getTestMessage();
        $validator->validate($message);
    }

    /**
     * @expectedException \Aws\Sns\Exception\InvalidSnsMessageException
     * @expectedExceptionMessage The message signature is invalid.
     */
    public function testValidateFailsWhenMessageIsInvalid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'Signature' => $this->getSignature('foo'),
        ]);
        $validator->validate($message);
    }

    public function testValidateSucceedsWhenMessageIsValid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage();

        // Get the signature for a real message
        $message['Signature'] = $this->getSignature($message->getStringToSign());

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    /**
     * @param array $customData
     *
     * @return Message
     */
    private function getTestMessage(array $customData = [])
    {
        return new Message($customData + [
            'Message'          => 'foo',
            'MessageId'        => 'bar',
            'Timestamp'        => time(),
            'TopicArn'         => 'baz',
            'Type'             => 'Notification',
            'SigningCertURL'   => self::VALID_CERT_URL,
            'Signature'        => true,
            'SignatureVersion' => '1',
        ]);
    }

    private function getMockHttpClient($responseBody = '')
    {
        return function () use ($responseBody) {
            return $responseBody;
        };
    }

    private function getMockCertServerClient()
    {
        return function ($url) {
            if ($url !== self::VALID_CERT_URL) {
                return '';
            }

            return self::$certificate;
        };
    }

    private function getSignature($stringToSign)
    {
        openssl_sign($stringToSign, $signature, self::$pKey);

        return base64_encode($signature);
    }
}
