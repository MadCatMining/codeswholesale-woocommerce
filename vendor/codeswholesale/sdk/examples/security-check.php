<?php
use CodesWholesale\ClientBuilder;
use CodesWholesale\Resource\Security;

session_start();

require_once '../vendor/autoload.php';
require_once 'utils.php';

$params = [
    /**
     * API Keys
     * These are common api keys, you can use it to test integration.
     */
    'cw.client_id' => 'ff72ce315d1259e822f47d87d02d261e',
    'cw.client_secret' => '$2a$10$E2jVWDADFA5gh6zlRVcrlOOX01Q/HJoT6hXuDMJxek.YEo.lkO2T6',
    /**
     * CodesWholesale ENDPOINT
     */
    'cw.endpoint_uri' => \CodesWholesale\CodesWholesale::SANDBOX_ENDPOINT,
    /**
     * Due to security reasons you should use SessionStorage only while testing.
     * In order to go live you should change it do database storage.
     *
     * If you want to use database storage use the code below.
     *
     * new \CodesWholesale\Storage\TokenDatabaseStorage(
     * new PDO('mysql:host=localhost;dbname=your_db_name', 'username', 'password'))
     *
     * Also remember to use SQL code included in import.sql file
     *
     */
    'cw.token_storage' => new \CodesWholesale\Storage\TokenSessionStorage()
];

$clientBuilder = new ClientBuilder($params);
$client = $clientBuilder->build();

$securityInformation = Security::check(
    "devteam@codeswholesale.com",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
    "devteam-payment@codeswholesale.com",
    "81.90.190.200"
);
displaySecurityCheck($securityInformation);


