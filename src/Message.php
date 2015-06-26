<?php
namespace Aws\Sns;

/**
 * Represents an SNS message received over http(s).
 */
class Message implements \ArrayAccess, \IteratorAggregate
{
    private static $requiredKeys = [
        '__default' => [
            'Message',
            'MessageId',
            'Timestamp',
            'TopicArn',
            'Type',
            'Signature',
            'SigningCertURL',
        ],
        'SubscriptionConfirmation' => [
            'SubscribeURL',
            'Token',
        ],
        'UnsubscribeConfirmation' => [
            'SubscribeURL',
            'Token',
        ],
    ];

    private static $signableKeys = [
        'Message',
        'MessageId',
        'Subject',
        'SubscribeURL',
        'Timestamp',
        'Token',
        'TopicArn',
        'Type',
    ];

    /** @var array The message data */
    private $data;

    /**
     * Creates a message object from the raw POST data
     *
     * @return Message
     * @throws \RuntimeException If the POST data is absent, or not a valid JSON document
     */
    public static function fromRawPostData()
    {
        if (!isset($_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE'])) {
            throw new \RuntimeException('SNS message type header not provided.');
        }

        $data = json_decode(file_get_contents('php://input'), true);
        if (JSON_ERROR_NONE !== json_last_error()) {
            throw new \InvalidArgumentException('Unable to parse JSON.');
        } elseif (!is_array($data)) {
            throw new \RuntimeException('Invalid POST data.');
        }

        return new Message($data);
    }

    /**
     * Creates a Message object from an array of raw message data.
     *
     * @param array $data The message data.
     *
     * @throws \InvalidArgumentException If a valid type is not provided or
     *                                   there are other required keys missing.
     */
    public function __construct(array $data)
    {
        // Make sure the type key is set
        if (!isset($data['Type'])) {
            throw new \InvalidArgumentException(
                'The "Type" must be provided to instantiate a Message object.'
            );
        }

        // Determine the required keys for this message type.
        $requiredKeys = array_merge(
            self::$requiredKeys['__default'],
            isset(self::$requiredKeys[$data['Type']]) ?
                self::$requiredKeys[$data['Type']]
                : []
        );

        // Ensure that all the required keys are provided.
        foreach ($requiredKeys as $key) {
            if (!isset($data[$key])) {
                throw new \InvalidArgumentException(
                    "Missing key {$key} in the provided data."
                );
            }
        }

        $this->data = $data;
    }

    public function getIterator()
    {
        return new \ArrayIterator($this->data);
    }

    /**
     * Builds a newline delimited string-to-sign according to the specs.
     *
     * @return string
     * @link http://docs.aws.amazon.com/sns/latest/gsg/SendMessageToHttp.verify.signature.html
     */
    public function getStringToSign()
    {
        $stringToSign = '';
        foreach (self::$signableKeys as $key) {
            if (isset($this[$key])) {
                $stringToSign .= "{$key}\n{$this[$key]}\n";
            }
        }

        return $stringToSign;
    }

    public function offsetExists($key)
    {
        return isset($this->data[$key]);
    }

    public function offsetGet($key)
    {
        return isset($this->data[$key]) ? $this->data[$key] : null;
    }

    public function offsetSet($key, $value)
    {
        $this->data[$key] = $value;
    }

    public function offsetUnset($key)
    {
        unset($this->data[$key]);
    }

    /**
     * Get all the message data as a plain array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->data;
    }
}
