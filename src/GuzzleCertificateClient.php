<?php
namespace Aws\Sns;

use Aws\Sns\Exception\CertificateRetrievalException;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\RequestException;

class GuzzleCertificateClient
{
    private $client;

    public function __construct(ClientInterface $client = null)
    {
        $this->client = $client ?: new Client();
    }

    public function __invoke($url)
    {
        try {
            $response = $this->client->request('GET', $url);
        } catch (RequestException $exception) {
            throw new CertificateRetrievalException(
                'Error encountered fetching signature verification certificate from SNS',
                $exception->hasResponse()
                    ? $exception->getResponse()->getStatusCode()
                    : 0,
                $exception
            );
        }

        if ($response->getStatusCode() === 200) {
            return (string) $response->getBody();
        }

        throw new CertificateRetrievalException(
            'Error encountered fetching signature verification certificate from SNS',
            $response->getStatusCode()
        );
    }
}
