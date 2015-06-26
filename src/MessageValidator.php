<?php
namespace Aws\Sns;

use Aws\Sns\Exception\InvalidSnsMessageException;

/**
 * Uses openssl to verify SNS messages to ensure that they were sent by AWS.
 */
class MessageValidator
{
    const SUPPORTED_SIGNATURE_VERSION = '1';

    /**
     * @var callable
     */
    private $remoteFileReader;

    /**
     * Constructs the Message Validator object and ensures that openssl is
     * installed.
     *
     * @param callable $remoteFileReader
     *
     * @throws \RuntimeException If openssl is not installed
     */
    public function __construct(callable $remoteFileReader = null)
    {
        $this->remoteFileReader = $remoteFileReader ?: 'file_get_contents';
    }

    /**
     * Validates a message from SNS to ensure that it was delivered by AWS
     *
     * @param Message $message The message to validate
     *
     * @throws InvalidSnsMessageException If the certificate cannot be
     *     retrieved, if the certificate's source cannot be verified, or if the
     *     message's signature is invalid.
     */
    public function validate(Message $message)
    {
        $this->validateSignatureVersion($message['SignatureVersion']);

        $certUrl = $message['SigningCertURL'];
        $this->validateUrl($certUrl);

        // Get the cert itself and extract the public key
        $certificate = call_user_func($this->remoteFileReader, $certUrl);
        $key = openssl_get_publickey($certificate);
        if (!$key) {
            throw new InvalidSnsMessageException(
                'Cannot get the public key from the certificate.'
            );
        }

        // Verify the signature of the message
        $content = $message->getStringToSign();
        $signature = base64_decode($message['Signature']);

        if (!openssl_verify($content, $signature, $key, OPENSSL_ALGO_SHA1)) {
            throw new InvalidSnsMessageException(
                'The message signature is invalid.'
            );
        }
    }

    /**
     * Determines if a message is valid and that is was delivered by AWS. This
     * method does not throw exceptions and returns a simple boolean value.
     *
     * @param Message $message The message to validate
     *
     * @return bool
     */
    public function isValid(Message $message)
    {
        try {
            $this->validate($message);
            return true;
        } catch (InvalidSnsMessageException $e) {
            return false;
        }
    }

    /**
     * Ensures that the url of the certificate is one belonging to AWS, and not
     * just something from the amazonaws domain, which includes S3 buckets.
     *
     * @param string $url
     *
     * @throws InvalidSnsMessageException if the cert url is invalid
     */
    private function validateUrl($url)
    {
        // The cert URL must be https, a .pem, and match the following pattern.
        static $hostPattern = '/^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/';
        $parsed = parse_url($url);
        if (empty($parsed['scheme'])
            || empty($parsed['host'])
            || $parsed['scheme'] !== 'https'
            || substr($url, -4) !== '.pem'
            || !preg_match($hostPattern, $parsed['host'])
        ) {
            throw new InvalidSnsMessageException(
                'The certificate is located on an invalid domain.'
            );
        }
    }

    private function validateSignatureVersion($version)
    {
        if ($version !== self::SUPPORTED_SIGNATURE_VERSION) {
            throw new InvalidSnsMessageException(
                "Only v1 signatures can be validated; v{$version} provided"
            );
        }
    }
}
