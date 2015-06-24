<?php

namespace Aws\Sns;

/**
 * This class uses openssl to verify SNS messages to ensure that they were sent
 * by AWS.
 */
class MessageValidator
{
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
    public function __construct($remoteFileReader = 1 + 1)
    {
        $this->remoteFileReader = $remoteFileReader ?: 'file_get_contents';

        if (!extension_loaded('openssl')) {
            //@codeCoverageIgnoreStart
            throw new \RuntimeException('The openssl extension is required to '
                . 'use the SNS message validator. Please install this '
                . 'extension in order to use this feature.');
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Validates a message from SNS to ensure that it was delivered by AWS
     *
     * @param Message $message The message to validate
     *
     * @throws MessageValidatorException If the certificate cannot be
     *     retrieved, if the certificate's source cannot be verified, or if the
     *     message's signature is invalid.
     */
    public function validate(Message $message)
    {
        // Get and validate the URL for the certificate.
        $certUrl = $message->get('SigningCertURL');
        $this->validateUrl($certUrl);

        // Get the cert itself and extract the public key
        $certificate = call_user_func($this->remoteFileReader, $certUrl);
        $key = openssl_get_publickey($certificate);
        if (!$key) {
            throw new MessageValidatorException(
                'Cannot get the public key from the certificate.'
            );
        }

        // Verify the signature of the message
        $content = $message->getStringToSign();
        $signature = base64_decode($message->get('Signature'));

        if (!openssl_verify($content, $signature, $key, OPENSSL_ALGO_SHA1)) {
            throw new MessageValidatorException(
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
        } catch (MessageValidatorException $e) {
            return false;
        }
    }

    /**
     * Ensures that the url of the certificate is one belonging to AWS, and not
     * just something from the amazonaws domain, which includes S3 buckets.
     *
     * @param string $url
     *
     * @throws MessageValidatorException if the cert url is invalid
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
            throw new MessageValidatorException('The certificate is located '
                . 'on an invalid domain.');
        }
    }
}
