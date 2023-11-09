<?php
namespace Aws\Sns;

use Aws\Sns\Exception\InvalidSnsMessageException;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * @covers Aws\Sns\MessageValidator
 */
class MessageValidatorTest extends TestCase
{
    const VALID_CERT_URL = 'https://sns.foo.amazonaws.com/bar.pem';

    private static $pKey;
    private static $certificate;

    public static function set_up_before_class()
    {
        self::$pKey = openssl_pkey_new();
        $csr = openssl_csr_new([], self::$pKey);
        $x509 = openssl_csr_sign($csr, null, self::$pKey, 1);
        openssl_x509_export($x509, self::$certificate);
        openssl_x509_free($x509);
    }

    public static function tear_down_after_class()
    {
        openssl_pkey_free(self::$pKey);
    }

    public function testIsValidReturnsFalseOnFailedValidation()
    {
        $validator = new MessageValidator($this->getMockHttpClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '2',
        ]);
        $this->assertFalse($validator->isValid($message));
    }

    public function testValidateFailsWhenSignatureVersionIsInvalid()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('The SignatureVersion "3" is not supported.');
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '3',
        ]);
        $validator->validate($message);
    }

    public function testValidateFailsWhenCertUrlInvalid()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('The certificate is located on an invalid domain.');
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar.pem',
        ]);
        $validator->validate($message);
    }

    public function testValidateFailsWhenCertUrlNotAPemFile()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('The certificate is located on an invalid domain.');
        $validator = new MessageValidator();
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.amazonaws.com/bar',
        ]);
        $validator->validate($message);
    }

    public function testValidatesAgainstCustomDomains()
    {
        $validator = new MessageValidator(
            function () {
                return self::$certificate;
            },
            '/^(foo|bar).example.com$/'
        );
        $message = $this->getTestMessage([
            'SigningCertURL' => 'https://foo.example.com/baz.pem',
        ]);
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message));
        $this->assertTrue($validator->isValid($message));
    }

    public function testValidateFailsWhenCannotGetCertificate()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectDeprecationMessageMatches('/Cannot get the certificate from ".+"./');
        $validator = new MessageValidator($this->getMockHttpClient(false));
        $message = $this->getTestMessage();
        $validator->validate($message);
    }

    public function testValidateFailsWhenCannotDeterminePublicKey()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('Cannot get the public key from the certificate.');
        $validator = new MessageValidator($this->getMockHttpClient());
        $message = $this->getTestMessage();
        $validator->validate($message);
    }

    public function testValidateFailsWhenMessageIsInvalid()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('The message signature is invalid.');
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'Signature' => $this->getSignature('foo'),
        ]);
        $validator->validate($message);
    }

    public function testValidateFailsWhenSha256MessageIsInvalid()
    {
        $this->expectException(InvalidSnsMessageException::class);
        $this->expectExceptionMessage('The message signature is invalid.');
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'Signature' => $this->getSignature('foo'),
             'SignatureVersion' => '2'

        ]);
        $validator->validate($message);
    }

    public function testValidateSucceedsWhenMessageIsValid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage();

        // Get the signature for a real message
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message));

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    public function testValidateSucceedsWhenSha256MessageIsValid()
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = $this->getTestMessage([
            'SignatureVersion' => '2'
        ]);

        // Get the signature for a real message
        $message['Signature'] = $this->getSignature($validator->getStringToSign($message), '2');

        // The message should validate
        $this->assertTrue($validator->isValid($message));
    }

    public function testBuildsStringToSignCorrectly()
    {
        $validator = new MessageValidator();
        $stringToSign = <<< STRINGTOSIGN
Message
foo
MessageId
bar
Timestamp
1435697129
TopicArn
baz
Type
Notification

STRINGTOSIGN;

        $this->assertEquals(
            $stringToSign,
            $validator->getStringToSign($this->getTestMessage())
        );
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

    private function getSignature($stringToSign, $algo = '1')
    {
        if ($algo === '2') {
            openssl_sign($stringToSign, $signature, self::$pKey, 'SHA256');
        } else {
            openssl_sign($stringToSign, $signature, self::$pKey);
        }

        return base64_encode($signature);
    }
}

function time()
{
    return 1435697129;
}
