# Amazon SNS message Validator for PHP

[![@awsforphp on Twitter](http://img.shields.io/badge/twitter-%40awsforphp-blue.svg?style=flat)](https://twitter.com/awsforphp)
[![Total Downloads](https://img.shields.io/packagist/dt/aws/aws-php-sns-message-validator.svg?style=flat)](https://packagist.org/packages/aws/aws-php-sns-message-validator)
[![Build Status](https://img.shields.io/travis/aws/aws-php-sns-message-validator.svg?style=flat)](https://travis-ci.org/aws/aws-php-sns-message-validator)
[![Apache 2 License](https://img.shields.io/packagist/l/aws/aws-php-sns-message-validator.svg?style=flat)](http://aws.amazon.com/apache-2-0/)

The **Amazon SNS Message Validator for PHP** allows you to validate that incoming
HTTP(S) messages are legitimate SNS notifications. This library does not depend
on the AWS SDK for PHP or Guzzle, but it does require that the OpenSSL PHP 
extension be installed.

## Usage

```php
<?php

require 'vendor/autoload.php';

use Aws\Sns\Message;
use Aws\Sns\MessageValidator;
 
$message = Message::fromRawPostData();
 
// Validate the message
$validator = new MessageValidator();
if ($validator->isValid($message)) {
   // do something with the message
}
```

### Thanks

A special thanks goes out to [Julian Vidal](https://github.com/poisa) who helped
create the [initial implementation](https://github.com/aws/aws-sdk-php/tree/2.8/src/Aws/Sns/MessageValidator)
in Version 2 of the [AWS SDK for PHP](https://github.com/aws/aws-sdk-php).
