<?php
namespace Aws\Sns;

/**
 * @covers Aws\Sns\Message
 */
class MessageTest extends \PHPUnit_Framework_TestCase
{
    public $messageData = array(
        'Message' => 'a',
        'MessageId' => 'b',
        'Timestamp' => 'c',
        'TopicArn' => 'd',
        'Type' => 'e',
        'Subject' => 'f',
        'Signature' => 'g',
        'SignatureVersion' => '1',
        'SigningCertURL' => 'h',
        'SubscribeURL' => 'i',
        'Token' => 'j',
    );

    public function testGetters()
    {
        $message = new Message($this->messageData);
        $this->assertInternalType('array', $message->toArray());

        foreach ($this->messageData as $key => $expectedValue) {
            $this->assertTrue(isset($message[$key]));
            $this->assertEquals($expectedValue, $message[$key]);
        }
    }

    public function testFactorySucceedsWithGoodData()
    {
        $this->assertInstanceOf('Aws\Sns\Message', new Message($this->messageData));
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testFactoryFailsWithNoType()
    {
        $data = $this->messageData;
        unset($data['Type']);
        new Message($data);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testFactoryFailsWithMissingData()
    {
        new Message(['Type' => 'Notification']);
    }

    public function testCanCreateFromRawPost()
    {
        $_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE'] = 'Notification';

        // Prep php://input with mocked data
        MockPhpStream::setStartingData(json_encode($this->messageData));
        stream_wrapper_unregister('php');
        stream_wrapper_register('php', __NAMESPACE__ . '\MockPhpStream');

        $message = Message::fromRawPostData();
        $this->assertInstanceOf('Aws\Sns\Message', $message);

        stream_wrapper_restore("php");
        unset($_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE']);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testCreateFromRawPostFailsWithMissingHeader()
    {
        Message::fromRawPostData();
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testCreateFromRawPostFailsWithMissingData()
    {
        $_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE'] = 'Notification';
        Message::fromRawPostData();
        unset($_SERVER['HTTP_X_AMZ_SNS_MESSAGE_TYPE']);
    }
}
