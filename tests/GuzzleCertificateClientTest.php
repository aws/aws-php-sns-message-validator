<?php
namespace Aws\Sns;

use Aws\Sns\Exception\CertificateRetrievalException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

class GuzzleCertificateClientTest extends \PHPUnit_Framework_TestCase
{
    public function testReturnsTheStringBodyOfAGuzzleResponse()
    {
        $client = new Client(['handler' => function () {
            return Promise\promise_for(new Response(200, [], 'CERT'));
        }]);
        $certClient = new GuzzleCertificateClient($client);

        $this->assertSame('CERT', $certClient('https://example.com'));
    }

    /**
     * @expectedException \Aws\Sns\Exception\CertificateRetrievalException
     * @expectedExceptionCode 500
     */
    public function testConvertsRequestExceptionToCertException()
    {
        $client = new Client(['handler' => function (Request $request) {
            return Promise\rejection_for(
                new RequestException('Not found', $request, new Response(500))
            );
        }]);
        $certClient = new GuzzleCertificateClient($client);

        $certClient('https://example.com');
    }

    /**
     * @expectedException \Aws\Sns\Exception\CertificateRetrievalException
     * @expectedExceptionCode 301
     */
    public function testConvertsNon200ResponseToCertException()
    {
        $client = new Client(['handler' => function () {
            return Promise\promise_for(new Response(301, [
                'Location' => 'https://www.malicious-domain.com/dont-go-here',
            ]));
        }]);
        $certClient = new GuzzleCertificateClient($client);

        $certClient('https://example.com');
    }
}
