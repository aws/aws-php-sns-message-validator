<?php
namespace Aws\Sns;

use Aws\Sns\Exception\InvalidSnsMessageException;

/**
 * Uses openssl to verify SNS messages to ensure that they were sent by AWS.
 */
class MessageValidator
{
    const SIGNATURE_VERSION_1 = '1';
    const SIGNATURE_VERSION_2 = '2';

    private static $signableKeysByType = [
        'Notification' => [
            'Message',
            'MessageId',
            'Subject',
            'Timestamp',
            'TopicArn',
            'Type',
        ],
        'SubscriptionConfirmation' => [
            'Message',
            'MessageId',
            'SubscribeURL',
            'Timestamp',
            'Token',
            'TopicArn',
            'Type',
        ],
        'UnsubscribeConfirmation' => [
            'Message',
            'MessageId',
            'SubscribeURL',
            'Timestamp',
            'Token',
            'TopicArn',
            'Type',
        ],
    ];

    /**
     * @var callable Callable used to download the certificate content.
     */
    private $certClient;

    /** @var string */
    private $hostPattern;

    /**
     * @var string  A pattern that will match all regional SNS endpoints, e.g.:
     *                  - sns.<region>.amazonaws.com        (AWS)
     *                  - sns.us-gov-west-1.amazonaws.com   (AWS GovCloud)
     *                  - sns.cn-north-1.amazonaws.com.cn   (AWS China)
     */
    private static $defaultHostPattern
        = '/^sns\.[a-zA-Z0-9\-]{3,}\.amazonaws\.com(\.cn)?$/';

    private static function isLambdaStyle(Message $message)
    {
        $messageData = $message->toArray();

        return array_key_exists('SigningCertUrl', $messageData)
            || array_key_exists('SubscribeUrl', $messageData)
            || array_key_exists('UnsubscribeUrl', $messageData);
    }

    private static function convertLambdaMessage(Message $message)
    {
        $messageData = $message->toArray();
        $keyReplacements = [
            'SigningCertUrl' => 'SigningCertURL',
            'SubscribeUrl' => 'SubscribeURL',
            'UnsubscribeUrl' => 'UnsubscribeURL',
        ];

        foreach ($keyReplacements as $lambdaKey => $canonicalKey) {
            if (array_key_exists($lambdaKey, $messageData)) {
                $message[$canonicalKey] = $message[$lambdaKey];
                unset($message[$lambdaKey]);
            }
        }
    }

    /**
     * Constructs the Message Validator object and ensures that openssl is
     * installed.
     *
     * @param callable $certClient Callable used to download the certificate.
     *                             Should have the following function signature:
     *                             `function (string $certUrl) : string|false $certContent`
     * @param string $hostNamePattern
     */
    public function __construct(
        ?callable $certClient = null,
        $hostNamePattern = ''
    ) {
        $this->certClient = $certClient ?: function($certUrl) {
            return @ file_get_contents($certUrl);
        };
        $this->hostPattern = $hostNamePattern ?: self::$defaultHostPattern;
    }

    /**
     * Validates a message from SNS to ensure that it was delivered by AWS.
     *
     * Lambda-style URL keys are canonicalized on the provided message after
     * successful validation.
     *
     * @param Message $message Message to validate.
     *
     * @throws InvalidSnsMessageException If the cert cannot be retrieved or its
     *                                    source verified, or the message
     *                                    signature is invalid.
     */
    public function validate(Message $message)
    {
        $messageToValidate = $message;
        if (self::isLambdaStyle($message)) {
            $messageToValidate = clone $message;
            self::convertLambdaMessage($messageToValidate);
        }

        $content = $this->getStringToSign($messageToValidate);

        // Get the certificate.
        $certUrl = $messageToValidate['SigningCertURL'];
        $this->validateUrl($certUrl);
        $certificate = call_user_func(
            $this->certClient,
            $certUrl
        );
        if ($certificate === false) {
            throw new InvalidSnsMessageException(
                "Cannot get the certificate from \"{$certUrl}\"."
            );
        }

        // Extract the public key.
        $key = openssl_get_publickey($certificate);
        if (!$key) {
            throw new InvalidSnsMessageException(
                'Cannot get the public key from the certificate.'
            );
        }

        // Verify the signature of the message.
        $signature = base64_decode($messageToValidate['Signature']);
        $algo = $messageToValidate['SignatureVersion']
            === self::SIGNATURE_VERSION_1
            ? OPENSSL_ALGO_SHA1
            : OPENSSL_ALGO_SHA256;
        if (openssl_verify($content, $signature, $key, $algo) !== 1) {
            throw new InvalidSnsMessageException(
                'The message signature is invalid.'
            );
        }

        if ($messageToValidate !== $message) {
            self::convertLambdaMessage($message);
        }
    }

    /**
     * Determines if a message is valid and that is was delivered by AWS. This
     * method does not throw exceptions and returns a simple boolean value.
     *
     * The provided message is not modified.
     *
     * @param Message $message The message to validate
     *
     * @return bool
     */
    public function isValid(Message $message)
    {
        try {
            $this->validate(clone $message);
            return true;
        } catch (InvalidSnsMessageException $e) {
            return false;
        }
    }

    /**
     * Builds string-to-sign according to the SNS message spec.
     *
     * @param Message $message Message for which to build the string-to-sign.
     *
     * @return string
     * @link http://docs.aws.amazon.com/sns/latest/gsg/SendMessageToHttp.verify.signature.html
     */
    public function getStringToSign(Message $message)
    {
        if ($message['SignatureVersion'] !== self::SIGNATURE_VERSION_1
            && $message['SignatureVersion'] !== self::SIGNATURE_VERSION_2) {
            throw new InvalidSnsMessageException(
                "The SignatureVersion \"{$message['SignatureVersion']}\" is not supported."
            );
        }

        $type = $message['Type'];
        if (!is_string($type) || !isset(self::$signableKeysByType[$type])) {
            throw new InvalidSnsMessageException(
                'The SNS message Type is not supported.'
            );
        }

        $stringToSign = '';
        foreach (self::$signableKeysByType[$type] as $key) {
            if (!isset($message[$key])) {
                if ($key === 'Subject') {
                    continue;
                }

                throw new InvalidSnsMessageException(
                    "The SNS message field \"{$key}\" is required."
                );
            }

            $value = $message[$key];
            if (!is_scalar($value)) {
                throw new InvalidSnsMessageException(
                    "The SNS message field \"{$key}\" must be a scalar value."
                );
            }
            $value = (string) $value;

            // Message and Subject may contain newlines. Newlines in signed
            // metadata would make the field-delimited string ambiguous.
            if ($key !== 'Message'
                && $key !== 'Subject'
                && strpbrk($value, "\r\n") !== false
            ) {
                throw new InvalidSnsMessageException(
                    "The SNS message field \"{$key}\" must not contain newlines."
                );
            }

            $stringToSign .= "{$key}\n{$value}\n";
        }

        return $stringToSign;
    }

    /**
     * Ensures that the URL of the certificate is one belonging to AWS, and not
     * just something from the amazonaws domain, which could include S3 buckets.
     *
     * @param string $url Certificate URL
     *
     * @throws InvalidSnsMessageException if the cert url is invalid.
     */
    private function validateUrl($url)
    {
        $parsed = parse_url($url);
        if (empty($parsed['scheme'])
            || empty($parsed['host'])
            || $parsed['scheme'] !== 'https'
            || substr($url, -4) !== '.pem'
            || !preg_match($this->hostPattern, $parsed['host'])
        ) {
            throw new InvalidSnsMessageException(
                'The certificate is located on an invalid domain.'
            );
        }
    }
}
