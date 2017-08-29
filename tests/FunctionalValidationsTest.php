<?php

namespace Aws\Sns;

/**
 * @covers Aws\Sns\MessageValidator
 * @covers Aws\Sns\Message
 */
class FunctionalValidationsTest extends \PHPUnit_Framework_TestCase
{
    private static $certificate =
'-----BEGIN CERTIFICATE-----
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
6Kw4sQp+ZMgtgzM8l3fDTMEgqpLSQH+2
-----END CERTIFICATE-----';

    public function getHttpFixtures()
    {
        return [
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "9438aee6-d476-5e20-ba25-ff24bf09d6ce",
                    'TopicArn' => "arn:aws:sns:us-west-2:604091128280:testing1",
                    'Subject' => "A subject",
                    'Message' => "A message",
                    'Timestamp' => "2017-06-20T00:15:59.380Z",
                    'SignatureVersion' => "1",
                    'Signature' => "WT7qMHW+jPdj/brSAX7M1jbP5OoPjn9pYmGQqrWeQgbMyVvz3D2sV72ldhCxQLqj/3TLtcTyErVqzT3AfQ8Vk55Rzxd1xnBufJ+0vIyH98b82pKOqRHOqlB72la5nY9/GF/p71BXmIChQpfv/CEZumexgLWnweJsqSMe82I6/eMmrhVZdKpBvz4Sqj+wNQW+0eYEc9bdZmEKuYIvrvTGm1MWkXmqUGuCGj5o3vFFn1GTtM895B3MyMgaSeDHI08CVfs9y1nLcrxwMvqpkHZmIwTi1jzSipYMRD8FVF6Wvq0Scy+FoYSnOWHpEsELI0SGddSqYgli9ROYiqi3DQhvHw==",
                    'SigningCertURL' => "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem",
                    'UnsubscribeURL' => "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:604091128280:testing1:b061e4fd-c468-458d-9736-91c8c0c18e29",
                ]
            ],
            [
                [
                    'Type' => "Notification",
                    'MessageId' => "7317aaf2-e97a-5cf3-8123-fb3a48fabd2a",
                    'TopicArn' => "arn:aws:sns:us-west-2:604091128280:testing1",
                    'Message' => "A subject-less message",
                    'Timestamp' => "2017-06-24T17:20:00.581Z",
                    'SignatureVersion' => "1",
                    'Signature' => "Lvtgxo8P2C3XUKT8fC7sfMRhxoK6dn/ed9B1DClmJ9GNuFF73G27lhKUsKWrLReawa+v7C1UY49qQb+lSMsBiTV0Hx7L2OKJjzll4fx+G09h2P8OK43Jk6/W05+xU0uvch6Ktp3XrBcI6KNyGFio5GAR2rCBHjdh8MsEYAWRtaVCBqJTLqnHscivOJD8u/m807wDbDhh9cQ5WnvjerUjtrDAfQJN5vHLjEPbL1owtu2FzC3rOHUL9j4TGOdZi2jhUYv8jwzNnJ05bhbtKd6HxKcTcv1JCp/4NLPa8LWYnbLRvWooDQdF2hr56EF6EKDzTtAWagoNYztwSvosQXNK+Q==",
                    'SigningCertURL' => "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem",
                    'UnsubscribeURL' => "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:604091128280:testing1:f0dd49ac-c33d-471e-812d-1f0e5116c711",
                ]
            ],
        ];
    }

    public function getLambdaFixtures()
    {
        return [
            [
                [
                    'Type' => 'Notification',
                    'MessageId' => '9438aee6-d476-5e20-ba25-ff24bf09d6ce',
                    'TopicArn' => 'arn:aws:sns:us-west-2:604091128280:testing1',
                    'Subject' => 'A subject',
                    'Message' => 'A message',
                    'Timestamp' => '2017-06-20T00:15:59.380Z',
                    'SignatureVersion' => '1',
                    'Signature' => 'WT7qMHW+jPdj/brSAX7M1jbP5OoPjn9pYmGQqrWeQgbMyVvz3D2sV72ldhCxQLqj/3TLtcTyErVqzT3AfQ8Vk55Rzxd1xnBufJ+0vIyH98b82pKOqRHOqlB72la5nY9/GF/p71BXmIChQpfv/CEZumexgLWnweJsqSMe82I6/eMmrhVZdKpBvz4Sqj+wNQW+0eYEc9bdZmEKuYIvrvTGm1MWkXmqUGuCGj5o3vFFn1GTtM895B3MyMgaSeDHI08CVfs9y1nLcrxwMvqpkHZmIwTi1jzSipYMRD8FVF6Wvq0Scy+FoYSnOWHpEsELI0SGddSqYgli9ROYiqi3DQhvHw==',
                    'SigningCertUrl' => 'https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem',
                    'UnsubscribeUrl' => 'https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:604091128280:testing1:7118d01a-202e-4a65-a372-f46b0994bdae',
                ]
            ],
            [
                [
                    'Type' => 'Notification',
                    'MessageId' => '7317aaf2-e97a-5cf3-8123-fb3a48fabd2a',
                    'TopicArn' => 'arn:aws:sns:us-west-2:604091128280:testing1',
                    'Subject' => null,
                    'Message' => 'A subject-less message',
                    'Timestamp' => '2017-06-24T17:20:00.581Z',
                    'SignatureVersion' => '1',
                    'Signature' => 'Lvtgxo8P2C3XUKT8fC7sfMRhxoK6dn/ed9B1DClmJ9GNuFF73G27lhKUsKWrLReawa+v7C1UY49qQb+lSMsBiTV0Hx7L2OKJjzll4fx+G09h2P8OK43Jk6/W05+xU0uvch6Ktp3XrBcI6KNyGFio5GAR2rCBHjdh8MsEYAWRtaVCBqJTLqnHscivOJD8u/m807wDbDhh9cQ5WnvjerUjtrDAfQJN5vHLjEPbL1owtu2FzC3rOHUL9j4TGOdZi2jhUYv8jwzNnJ05bhbtKd6HxKcTcv1JCp/4NLPa8LWYnbLRvWooDQdF2hr56EF6EKDzTtAWagoNYztwSvosQXNK+Q==',
                    'SigningCertUrl' => 'https://sns.us-west-2.amazonaws.com/SimpleNotificationService-b95095beb82e8f6a046b3aafc7f4149a.pem',
                    'UnsubscribeUrl' => 'https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:604091128280:testing1:7118d01a-202e-4a65-a372-f46b0994bdae',
                ]
            ],
        ];
    }

    private function getMockCertServerClient()
    {
        return function () {
            return self::$certificate;
        };
    }

    /**
     * @dataProvider getHttpFixtures
     *
     * @param array $messageData
     */
    public function testValidatesHttpFixtures($messageData)
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = new Message($messageData);

        $this->assertTrue($validator->isValid($message));
        $this->assertNotEmpty($message['SigningCertURL']);
    }

    /**
     * @dataProvider getLambdaFixtures
     *
     * @param array $messageData
     */
    public function testValidatesLambdaFixtures($messageData)
    {
        $validator = new MessageValidator($this->getMockCertServerClient());
        $message = new Message($messageData);

        $this->assertTrue($validator->isValid($message));
        $this->assertNotEmpty($message['SigningCertUrl']);
    }
}
