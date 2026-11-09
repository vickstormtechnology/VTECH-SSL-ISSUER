<?php

/*
CertSage (support@certsage.com)
Copyright 2021-2026 Griffin Software (https://griffin.software)

PHP 7.0+ required

Permission is granted to distribute this software in its original form.
Permission is denied to distribute any works derived from this software.
No guarantees or warranties of any kind are made as to the fitness of this software for any purpose.
Usage of this software constitutes acceptance of full liability for any consequences resulting from its usage.
*/

namespace CertSage;
use Exception;

$version = "3.3.1";
$dataDirectory = "../CertSage";

function createDirectory($directory)
{
  clearstatcache(true, $directory);

  if (is_dir($directory))
    return;

  if (!mkdir($directory, 0755))
    throw new Exception("could not create directory: $directory");
}

function fileExists($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  clearstatcache(true, $filename);

  return is_file($filename);
}

function touchFile($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  if (!touch($filename))
    throw new Exception("could not touch file: $filename");
}

function writeFile($filename, $data, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
  {
    createDirectory($dataDirectory);
    $filename = "$dataDirectory/$filename";
  }

  if (file_put_contents($filename, $data, LOCK_EX) === false)
    throw new Exception("could not write file: $filename");

  if (!chmod($filename, 0644))
    throw new Exception("could not set permissions for file: $filename");
}

function readFile($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  $data = file_get_contents($filename);

  if ($data === false)
    throw new Exception("could not read file: $filename");

  return $data;
}

function deleteFile($filename, $inDataDirectory = true)
{
  global $dataDirectory;

  if ($inDataDirectory)
    $filename = "$dataDirectory/$filename";

  if (!unlink($filename))
    throw new Exception("could not delete file: $filename");
}

function encodeJSON($value)
{
  $json = json_encode($value, JSON_UNESCAPED_SLASHES);

  if (json_last_error() != JSON_ERROR_NONE)
    throw new Exception("encode JSON failed");

  return $json;
}

function decodeJSON($json)
{
  $value = json_decode($json, true);

  if (json_last_error() != JSON_ERROR_NONE)
    throw new Exception("decode JSON failed");

  return $value;
}

function encodeBase64($string)
{
  return strtr(rtrim(base64_encode($string), "="), "+/", "-_");
}

function findHeader($response, $target, $required = true)
{
  $regex = "~^$target: ([^\r\n]+)[\r\n]*~i";
  foreach ($response["headers"] as $header)
  {
    $outcome = preg_match($regex, $header, $matches);

    if ($outcome === false)
      throw new Exception("regular expression match failed when extracting header");

    if ($outcome === 1)
      return $matches[1];
  }

  if ($required)
    throw new Exception("missing $target header");

  return null;
}

function sendRequest($url, $expectedResponseCode, $payload = null, $jwk = null)
{
  global $version;
  global $account;
  static $nonce = null;

  $headers = [];
  $headerSize = 0;

  $ch = curl_init($url);

  if ($ch === false)
    throw new Exception("cURL initialization failed");

  if (!curl_setopt($ch, CURLOPT_USERAGENT, "CertSage/" . $version . " (support@griffin.software)"))
    throw new Exception("cURL set user agent option failed");

  if (!curl_setopt($ch, CURLOPT_RETURNTRANSFER, true))
    throw new Exception("cURL set return transfer option failed");

  if (isset($payload))
  {
    if (!isset($nonce))
    {
      $response = sendRequest($account["acmeDirectory"]["newNonce"], 204);

      if (!isset($nonce))
        throw new Exception("get new nonce failed");
    }

    $protected = [
      "url"   => $url,
      "alg"   => "RS256",
      "nonce" => $nonce
    ];

    if (isset($jwk))
      $protected["jwk"] = $jwk;
    else
      $protected["kid"] = $account["URL"];

    $protected = encodeBase64(encodeJSON($protected));

    if ($payload !== "")
      $payload = encodeBase64(encodeJSON($payload));

    if (openssl_sign("$protected.$payload", $signature, $account["key"], "sha256WithRSAEncryption") === false)
      throw new Exception("openssl sign failed");

    $signature = encodeBase64($signature);

    $josejson = encodeJSON([
      "protected" => $protected,
      "payload"   => $payload,
      "signature" => $signature
    ]);

    if (!curl_setopt($ch, CURLOPT_POSTFIELDS, $josejson))
      throw new Exception("cURL set post fields option failed");

    if (!curl_setopt($ch, CURLOPT_HTTPHEADER, ["Content-Type: application/jose+json", "Content-Length: " . strlen($josejson)]))
      throw new Exception("cURL set http header option failed");
  }

  if (!curl_setopt($ch, CURLOPT_HEADER, true))
    throw new Exception("cURL set header option failed");

  if (!curl_setopt($ch, CURLOPT_HEADERFUNCTION,
         function($ch, $header) use (&$headers, &$headerSize)
         {
           $headers[] = $header;
           $length = strlen($header);
           $headerSize += $length;
           return $length;
         }))
    throw new Exception("cURL set header function option failed");

  $body = curl_exec($ch);

  if ($body === false)
    throw new Exception("cURL execution failed: $url");

  $account["responses"][] = $body;

  $responseCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

  if ($responseCode === false)
    throw new Exception("cURL get response code info failed");

  $length = strlen($body);

  if ($headerSize > $length)
    throw new Exception("improper response header size");

  $body =   $headerSize == $length
          ? ""
          : substr($body, $headerSize);

  if ($body === false)
    throw new Exception("could not truncate headers from response");

  $response = [
    "headers" => $headers,
    "body"    => $body
  ];

  if ($responseCode !== $expectedResponseCode)
  {
    if (findHeader($response, "content-type", false) === "application/problem+json")
    {
      $problem = decodeJSON($response["body"]);

      if (isset($problem["type"], $problem["detail"]))
        throw new Exception($problem["type"] . "<br>" . $problem["detail"]);
    }

    throw new Exception("unexpected response code: $responseCode vs $expectedResponseCode");
  }

  $nonce = findHeader($response, "replay-nonce", false);

  return $response;
}

function acquireCertificate($environment)
{
  global $dataDirectory;
  global $account;

  switch ($environment)
  {
    case "production":

      $filename = "account.key";
      $url = "https://acme-v02.api.letsencrypt.org/directory";
      break;

    case "staging":

      $filename = "account-staging.key";
      $url = "https://acme-staging-v02.api.letsencrypt.org/directory";
      break;
  }

  $accountKeyExists = fileExists($filename);

  if ($accountKeyExists)
  {
    $account["key"] = readFile($filename);

    $accountKeyObject = openssl_pkey_get_private($account["key"]);

    if ($accountKeyObject === false)
      throw new Exception("check account key failed");
  }
  else
  {
    $options = [
      "private_key_bits" => 2048,
      "private_key_type" => OPENSSL_KEYTYPE_RSA
    ];

    $accountKeyObject = openssl_pkey_new($options);

    if ($accountKeyObject === false)
      throw new Exception("generate account key failed");

    if (!openssl_pkey_export($accountKeyObject, $account["key"]))
      throw new Exception("export account key failed");
  }

  $accountKeyDetails = openssl_pkey_get_details($accountKeyObject);

  if ($accountKeyDetails === false)
    throw new Exception("get account key details failed");

  $jwk = [
    "e" => encodeBase64($accountKeyDetails["rsa"]["e"]),
    "kty" => "RSA",
    "n" => encodeBase64($accountKeyDetails["rsa"]["n"])
  ];

  $digest = openssl_digest(encodeJSON($jwk), "sha256", true);

  if ($digest === false)
    throw new Exception("digest JWK failed");

  $thumbprint = encodeBase64($digest);

  $response = sendRequest($url, 200);

  $account["acmeDirectory"] = decodeJSON($response["body"]);

  $url = $account["acmeDirectory"]["newAccount"];

  if ($accountKeyExists)
  {
    $payload = [
      "onlyReturnExisting" => true
    ];

    $response = sendRequest($url, 200, $payload, $jwk);
  }
  else
  {
    $payload = [
      "termsOfServiceAgreed" => true
    ];

    $response = sendRequest($url, 201, $payload, $jwk);

    writeFile($filename, $account["key"]);
  }

  $account["URL"] = findHeader($response, "location");

  if (!isset($_POST["identifiers"]))
    throw new Exception("identifiers was missing");

  if (!is_string($_POST["identifiers"]))
    throw new Exception("identifiers was not a string");

  $identifiers = [];

  for ($identifier = strtok($_POST["identifiers"], "\r\n");
       $identifier !== false;
       $identifier = strtok("\r\n"))
    $identifiers[] = [
      "type"  => "dns",
      "value" => $identifier
    ];

  $url = $account["acmeDirectory"]["newOrder"];

  $payload = [
    "identifiers" => $identifiers
  ];

  $response = sendRequest($url, 201, $payload);

  $orderurl = findHeader($response, "location");
  $order = decodeJSON($response["body"]);

  $authorizationurls = [];
  $challengeurls = [];
  $challengetokens = [];

  $payload = "";

  foreach ($order["authorizations"] as $url)
  {
    $response = sendRequest($url, 200, $payload);

    $authorization = decodeJSON($response["body"]);

    if ($authorization["status"] === "valid")
      continue;

    $authorizationurls[] = $url;

    foreach ($authorization["challenges"] as $challenge)
    {
      if ($challenge["type"] === "http-01")
      {
        $challengeurls[] = $challenge["url"];
        $challengetokens[] = $challenge["token"];
        continue 2;
      }
    }

    throw new Exception("no http-01 challenge found");
  }

  createDirectory("./.well-known");
  createDirectory("./.well-known/acme-challenge");

  try
  {
    foreach ($challengetokens as $challengetoken)
      writeFile("./.well-known/acme-challenge/$challengetoken",
                "$challengetoken.$thumbprint",
                false);

    sleep(2);

    $payload = (object)[];

    foreach ($challengeurls as $url)
      $challenge = sendRequest($url, 200, $payload);

    sleep(6);

    $payload = "";

    foreach ($authorizationurls as $url)
    {
      for ($attempt = 1; true; ++$attempt)
      {
        $response = sendRequest($url, 200, $payload);

        $authorization = decodeJSON($response["body"]);

        if ($authorization["status"] !== "pending")
          break;

        if ($attempt == 10)
          throw new Exception("authorization still pending after $attempt attempts");

        sleep(2);
      }

      if ($authorization["status"] !== "valid")
        throw new Exception($authorization["challenges"][0]["error"]["type"] . "<br>" . $authorization["challenges"][0]["error"]["detail"]);
    }
  }
  finally
  {
    foreach ($challengetokens as $challengetoken)
      deleteFile("./.well-known/acme-challenge/$challengetoken", false);
  }

  switch ($_POST["keyType"])
  {
    case "RSA":

      $options = [
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA
      ];
      break;

    case "EC":

      $options = [
        "curve_name" => "secp384r1",
        "private_key_type" => OPENSSL_KEYTYPE_EC
      ];
      break;

    default:

      throw new Exception("unknown keyType: " . $_POST["keyType"]);
  }

  $certificateKeyObject = openssl_pkey_new($options);

  if ($certificateKeyObject === false)
    throw new Exception("generate certificate key failed");

  if (!openssl_pkey_export($certificateKeyObject, $certificateKey))
    throw new Exception("export certificate key failed");

  $dn = [
    "commonName" => $identifiers[0]["value"]
  ];

  $options = [
    "digest_alg" => "sha256",
    "config" => "$dataDirectory/openssl.cnf"
  ];

  $opensslcnf =
    "[req]\n" .
    "distinguished_name = req_distinguished_name\n" .
    "req_extensions = v3_req\n\n" .
    "[req_distinguished_name]\n\n" .
    "[v3_req]\n" .
    "subjectAltName = @san\n\n" .
    "[san]\n";

  $i = 0;
  foreach ($identifiers as $identifier)
  {
    ++$i;
    $opensslcnf .= "DNS.$i = " . $identifier["value"] . "\n";
  }

  try
  {
    writeFile("openssl.cnf", $opensslcnf);

    $csrObject = openssl_csr_new($dn, $certificateKey, $options);

    if ($csrObject === false)
      throw new Exception("generate csr failed");
  }
  finally
  {
    deleteFile("openssl.cnf");
  }

  if (!openssl_csr_export($csrObject, $csr))
    throw new Exception("export csr failed");

  $url = $order["finalize"];

  $outcome = preg_match("~^-----BEGIN CERTIFICATE REQUEST-----([^\-]+)-----END CERTIFICATE REQUEST-----~",
                        str_replace("\n", "", $csr),
                        $matches);

  if ($outcome === false)
    throw new Exception("extract csr failed");

  if ($outcome === 0)
    throw new Exception("csr format mismatch");

  $payload = [
    "csr" => strtr(rtrim($matches[1], "="), "+/", "-_")
  ];

  $response = sendRequest($url, 200, $payload);

  $order = decodeJSON($response["body"]);

  if ($order["status"] !== "valid")
  {
    sleep(2);

    $url = $orderurl;

    $payload = "";

    for ($attempt = 1; true; ++$attempt)
    {
      $response = sendRequest($url, 200, $payload);

      $order = decodeJSON($response["body"]);

      if (!(   $order["status"] === "pending"
            || $order["status"] === "processing"
            || $order["status"] === "ready"))
        break;

      if ($attempt == 10)
        throw new Exception("order still pending after $attempt attempts");

      sleep(2);
    }

    if ($order["status"] !== "valid")
      throw new Exception("order failed");
  }

  sleep(2);

  $url = $order["certificate"];

  $payload = "";

  $response = sendRequest($url, 200, $payload);

  $certificate = $response["body"];

  if ($environment === "production")
  {
    writeFile("certificate.crt", $certificate);
    writeFile("certificate.key", $certificateKey);

    importCertificate();
  }
}

function importCertificate()
{
  global $certificate;
  global $account;

  $certificate = [];
  $certificate["valid"] = false;

  $certificateMissing    = !fileExists("certificate.crt");
  $certificateKeyMissing = !fileExists("certificate.key");

  if ($certificateMissing && $certificateKeyMissing)
    return;

  if ($certificateMissing)
    throw new Exception("certificate.crt file missing");

  if ($certificateKeyMissing)
    throw new Exception("certificate.key file missing");

  $outcome = preg_match("~^(-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END CERTIFICATE-----)~",
                        readFile("certificate.crt"),
                        $matches);

  if ($outcome === false)
    throw new Exception("extract certificate failed");

  if ($outcome === 0)
    throw new Exception("certificate format mismatch");

  $certificate["certificate"] = $matches[1];

  $certificateObject = openssl_x509_read($certificate["certificate"]);

  if ($certificateObject === false)
    throw new Exception("check certificate failed");

  $outcome = preg_match("~^(-----BEGIN PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{64}\n)*(?:(?:[A-Za-z0-9+/]{4}){0,15}(?:[A-Za-z0-9+/]{2}(?:[A-Za-z0-9+/]|=)=)?\n)?-----END PRIVATE KEY-----)~",
                        readFile("certificate.key"),
                        $matches);

  if ($outcome === false)
    throw new Exception("extract certificate private key failed");

  if ($outcome === 0)
    throw new Exception("certificate private key format mismatch");

  $certificate["key"] = $matches[1];

  $certificateKeyObject = openssl_pkey_get_private($certificate["key"]);

  if ($certificateKeyObject === false)
    throw new Exception("check certificate private key failed");

  if (!openssl_x509_check_private_key($certificateObject, $certificateKeyObject))
    throw new Exception("certificate and certificate private key do not correspond");

  $certificateData = openssl_x509_parse($certificateObject);

  if ($certificateData === false)
    throw new Exception("parse certificate failed");

  $url = "https://acme-v02.api.letsencrypt.org/directory";

  $response = sendRequest($url, 200);

  $account["acmeDirectory"] = decodeJSON($response["body"]);

  $aki = encodeBase64(hex2bin(str_replace(":", "", substr(rtrim($certificateData["extensions"]["authorityKeyIdentifier"]), 6))));

  $serialNumber = encodeBase64(hex2bin("00" . $certificateData["serialNumberHex"]));

  $url = $account["acmeDirectory"]["renewalInfo"] . "/$aki.$serialNumber";

  $response = sendRequest($url, 200);

  $ari = decodeJSON($response["body"]);

  $time = time();
  $certificate["validFrom"] = (int)$certificateData["validFrom_time_t"];
  $certificate["validTo"]   = (int)$certificateData["validTo_time_t"];
  $certificate["renewAt"]   = strtotime($ari["suggestedWindow"]["start"]);
  $certificate["renewNow"]  = $time >= $certificate["renewAt"];
  $certificate["expired"]   = $time >= $certificate["validTo"];

  $sans = explode(", ", $certificateData["extensions"]["subjectAltName"]);

  foreach ($sans as &$san)
  {
    list($type, $value) = explode(":", $san);

    if ($type !== "DNS")
      throw new Exception("Non-DNS SAN found in certificate");

    $san = $value;
  }

  unset($san);

  $certificate["identifiers"] = $sans;

  $certificateKeyObject = openssl_pkey_get_public($certificateObject);

  if ($certificateKeyObject === false)
    throw new Exception("check certificate public key failed");

  $certificateKeyDetails = openssl_pkey_get_details($certificateKeyObject);

  if ($certificateKeyDetails === false)
    throw new Exception("get certificate public key details failed");

  switch ($certificateKeyDetails["type"])
  {
    case OPENSSL_KEYTYPE_RSA:

      $certificate["keyType"] = "RSA";
      break;

    case OPENSSL_KEYTYPE_EC:

      $certificate["keyType"] = "EC";
      break;

    default:

      throw new Exception("unsupported keyType: " . $certificateKeyDetails["type"]);
  }

  $certificate["valid"] = true;
}

function installCertificate()
{
  global $certificate;

  $domain = $certificate["identifiers"][0];
  $domainLength = strlen($certificate["identifiers"][0]);

  foreach ($certificate["identifiers"] as $san)
  {
    $sanLength = strlen($san);

    if ($sanLength >= $domainLength)
      continue;

    $domain = $san;
    $domainLength = $sanLength;
  }

  $cert = rawurlencode($certificate["certificate"]);
  $key  = rawurlencode($certificate["key"]);

  unset($output);

  $return = exec("uapi SSL install_ssl domain=$domain cert=$cert key=$key --output=json", $output, $result_code);

  if ($return === false)
    throw new Exception("shell execution pipe could not be established");

  if ($result_code !== 0)
    throw new Exception("uapi SSL install_ssl failed");

  $output = json_decode(implode("\n", $output));

  if ($output->result->status === 0)
    throw new Exception(empty($output->result->errors) ? "uapi SSL install_ssl error" : implode("<br>", $output->result->errors));

  unset($output);

  $return = exec("uapi SSL toggle_ssl_redirect_for_domains domains=$domain state=1 --output=json", $output, $result_code);

  if ($return === false)
    throw new Exception("shell execution pipe could not be established");

  if ($result_code !== 0)
    throw new Exception("uapi SSL toggle_ssl_redirect_for_domains failed");

  $output = json_decode(implode("\n", $output));

  if ($output->result->status === 0)
    throw new Exception(empty($output->result->errors) ? "uapi SSL toggle_ssl_redirect_for_domains error" : implode("<br>", $output->result->errors));

  if (!fileExists("autorenew.txt"))
  {
    unset($output);

    $scriptName = basename(__FILE__);
    $return = exec("(crontab -l 2>/dev/null; echo 30 15 \\* \\* \\* curl -sS https://$domain/$scriptName?autorenew) | crontab -", $output, $result_code);

    if ($return === false)
      throw new Exception("shell execution pipe could not be established");

    if ($result_code !== 0)
      throw new Exception("failed while setting crontab");

    touchFile("autorenew.txt");
  }
}

// Session-based login logic
$isHttps = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off");
session_set_cookie_params(0, "/", "", $isHttps, true);
session_start();
$loginError = "";

if (isset($_GET["logout"]))
{
  $_SESSION = [];
  session_destroy();
  header("Location: " . strtok($_SERVER["REQUEST_URI"], "?"));
  exit;
}

if (isset($_POST["login_password"]))
{
  if (is_string($_POST["login_password"]) && $_POST["login_password"] === "4151342234")
  {
    session_regenerate_id(true);
    $_SESSION["certsage_authenticated"] = true;
    header("Location: " . strtok($_SERVER["REQUEST_URI"], "?"));
    exit;
  }
  $loginError = "Incorrect password. Please try again.";
}

$account = [];
$account["responses"] = [];

try
{
  importCertificate();

  if (isset($_GET["autorenew"]))
  {
    if (   $certificate["valid"]
        && $certificate["renewNow"])
    {
      $_POST["identifiers"] = implode("\n", $certificate["identifiers"]);
      $_POST["keyType"]     = $certificate["keyType"];
      acquireCertificate("production");
      importCertificate();
      installCertificate();
      $message = "certificate renewed";
    }
    else
      $message = "";
  }
  elseif (empty($_SESSION["certsage_authenticated"]))
  {
    $page = "login";
  }
  elseif (isset($_POST["action"]))
  {
    if (!is_string($_POST["action"]))
      throw new Exception("action was not a string");

    switch ($_POST["action"])
    {
      case "acquireandinstall":

        acquireCertificate("production");
        installCertificate();
        $message = "Certificate acquired and installed into cPanel.";
        break;

      case "acquire":

        acquireCertificate("production");
        $message = "Certificate acquired.";
        break;

      case "install":

        installCertificate();
        $message = "Certificate installed into cPanel.";
        break;

      case "test":

        acquireCertificate("staging");
        $message = "Test passed.";
        break;

      default:

        throw new Exception("unknown action: " . $_POST["action"]);
    }

    $page = "success";
  }
  else
  {
    createDirectory($dataDirectory);
    $page = "welcome";
  }
}
catch (Exception $e)
{
  $message = $e->getMessage();
  $page = "trouble";
}
finally
{
  writeFile("responses.txt", implode("\n\n-----\n\n", array_reverse($account["responses"])));
}

if (   !isset($_POST["action"])
    &&  isset($_GET["autorenew"]))
  exit($message);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VTECH Secure SSL Manager</title>
<meta name="author" content="Jonathan Griffin">
<meta name="description" content="VTECH">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0f172a">
<meta name="referrer" content="origin">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg-gradient: radial-gradient(circle at top right, #1e1b4b, #0f172a 60%);
  --panel-bg: rgba(30, 41, 59, 0.7);
  --border-color: rgba(255, 255, 255, 0.08);
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --accent: #38bdf8;
  --accent-hover: #0ea5e9;
  --error-bg: rgba(127, 29, 29, 0.3);
  --error-border: rgba(248, 113, 113, 0.3);
  --error-text: #fca5a5;
}

* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

html {
  min-height: 100%;
  background: var(--bg-gradient);
  font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
  color: var(--text-primary);
}

body {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  max-width: 540px;
  margin: 0 auto;
  padding: 24px 16px;
}

header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  background: var(--panel-bg);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border-color);
  border-radius: 16px;
  margin-bottom: 24px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
}

header ul {
  list-style: none;
  display: flex;
  align-items: center;
  gap: 12px;
}

header ul li:first-of-type {
  font-weight: 700;
  font-size: 1.1rem;
  display: flex;
  align-items: center;
  gap: 8px;
}

header ul li:not(:first-of-type) {
  font-size: 0.8rem;
  color: var(--text-secondary);
}

header a.logout-btn {
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
  border: 1px solid rgba(239, 68, 68, 0.3);
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 0.8rem;
  font-weight: 600;
  text-decoration: none;
  transition: all 0.2s ease;
}

header a.logout-btn:hover {
  background: rgba(239, 68, 68, 0.25);
}

img#logo {
  width: 24px;
  height: 24px;
}

main {
  background: var(--panel-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border-color);
  border-radius: 24px;
  padding: 32px;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

h1 {
  font-size: 1.75rem;
  font-weight: 700;
  margin-bottom: 12px;
  letter-spacing: -0.02em;
}

p {
  color: var(--text-secondary);
  font-size: 0.95rem;
  line-height: 1.5;
  margin-bottom: 20px;
}

a {
  color: var(--accent);
  text-decoration: none;
}

a:hover {
  text-decoration: underline;
}

.error-box {
  background: var(--error-bg);
  border: 1px solid var(--error-border);
  color: var(--error-text);
  padding: 12px 16px;
  border-radius: 12px;
  font-size: 0.9rem;
  margin-bottom: 20px;
}

label {
  display: block;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--text-secondary);
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

input[type="password"], textarea {
  width: 100%;
  background: rgba(15, 23, 42, 0.6);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 14px 16px;
  color: var(--text-primary);
  font-family: inherit;
  font-size: 1rem;
  transition: all 0.2s ease;
  outline: none;
  margin-bottom: 20px;
}

input[type="password"]:focus, textarea:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15);
}

textarea {
  resize: vertical;
  min-height: 120px;
}

.radio-group {
  display: flex;
  gap: 20px;
  margin-bottom: 24px;
}

.radio-label {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-primary);
  font-size: 0.95rem;
  cursor: pointer;
  text-transform: none;
  letter-spacing: normal;
}

input[type="radio"] {
  accent-color: var(--accent);
  width: 18px;
  height: 18px;
}

.button-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

button[type="submit"] {
  background: linear-gradient(135deg, var(--accent), var(--accent-hover));
  color: #0f172a;
  border: none;
  border-radius: 12px;
  padding: 14px 20px;
  font-family: inherit;
  font-weight: 700;
  font-size: 0.95rem;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 4px 12px rgba(56, 189, 248, 0.25);
  text-align: center;
}

button[type="submit"]:hover {
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(56, 189, 248, 0.4);
}

button[type="submit"]:active {
  transform: translateY(1px);
}

button.full-width {
  grid-column: span 2;
}

.cert-details {
  background: rgba(15, 23, 42, 0.4);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 20px;
  font-size: 0.9rem;
}

.cert-details div {
  margin-bottom: 6px;
}

.cert-details div:last-child {
  margin-bottom: 0;
}

footer {
  text-align: center;
  padding-top: 24px;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

footer ul {
  list-style: none;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

footer a {
  color: var(--text-secondary);
}

footer a:hover {
  color: var(--accent);
}

#wait {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(8px);
  z-index: 999;
  place-content: center;
  text-align: center;
}

#hourglass {
  font-size: 48px;
  animation: pulse 1.5s infinite ease-in-out;
}

@keyframes pulse {
  0%, 100% { opacity: 0.4; transform: scale(0.95); }
  50% { opacity: 1; transform: scale(1.05); }
}

@media (max-width: 480px) {
  .button-grid {
    grid-template-columns: 1fr;
  }
  button.full-width {
    grid-column: span 1;
  }
}
</style>
</head>
<body>
<header>
<ul>
<li><img id="logo" src="https://certsage.com/images/logo.png" alt="logo"> VTECH SSL</li>
<li>v<?= $version ?></li>
</ul>
<?php if (!empty($_SESSION["certsage_authenticated"])): ?>
<a class="logout-btn" href="?logout=1">Sign Out</a>
<?php endif; ?>
</header>

<main>
<?php if (empty($_SESSION["certsage_authenticated"])): ?>
  <div>
    <h1>System Login</h1>
    <p>Please enter your secure access password to manage SSL certificates.</p>
    <?php if ($loginError !== ""): ?>
      <div class="error-box"><?= htmlspecialchars($loginError, ENT_QUOTES, "UTF-8") ?></div>
    <?php endif; ?>
    <form autocomplete="off" method="post">
      <label for="login_password">Access Password</label>
      <input id="login_password" name="login_password" type="password" required autofocus placeholder="Enter password">
      <button type="submit" class="full-width" style="width: 100%;">Authenticate</button>
    </form>
  </div>
<?php else: ?>
  <?php
    switch ($page):
      case "welcome":
  ?>
  <h1>Welcome Back</h1>
  <p>VTECH SSL is your secure ACME client for managing <a href="https://letsencrypt.org/" target="_blank">Let's Encrypt</a> DV TLS/SSL certificates effortlessly.</p>
  <?php
        break;
      case "success":
  ?>
  <h1>Operation Successful</h1>
  <p><?= $message ?></p>
  <?php
        break;
      case "trouble":
  ?>
  <h1>Notice / Error</h1>
  <p><?= $message ?></p>
  <?php
        break;
    endswitch;
  ?>

  <form autocomplete="off" method="post" onsubmit="document.getElementById('wait').style.display = 'grid';">
  <?php
    if ($certificate["valid"]):
  ?>
  <div class="cert-details">
    <div style="font-weight: 600; margin-bottom: 8px; color: var(--text-primary);">Existing Certificate Status</div>
    <div style="color: #4ade80;">Issued: <?= gmdate("M j, Y g:i:s A", $certificate["validFrom"]); ?> UTC</div>
    <div style="color: <?= $certificate["renewNow"] ? "#facc15" : "#4ade80" ?>;">Renew: <?= gmdate("M j, Y g:i:s A", $certificate["renewAt"]); ?> UTC</div>
    <div style="color: <?= $certificate["expired"] ? "#f87171" : "#4ade80" ?>;">Expiry: <?= gmdate("M j, Y g:i:s A", $certificate["validTo"]); ?> UTC</div>
  </div>
  <?php
    endif;
  ?>

  <div style="margin-bottom: 20px;">
    <label for="identifiers">Domain and Subdomain Names</label>
    <p style="font-size: 0.8rem; margin-bottom: 8px;">One per line; No wildcards (*)</p>
    <textarea id="identifiers" name="identifiers" rows="4"><?= $certificate["valid"] ? implode("\n", $certificate["identifiers"]) : "" ?></textarea>
  </div>

  <div style="margin-bottom: 24px;">
    <label>Certificate Key Type</label>
    <div class="radio-group">
      <label class="radio-label">
        <input name="keyType" value="RSA" type="radio" <?= (!$certificate["valid"] || $certificate["keyType"] === "RSA") ? "checked" : "" ?>> RSA (Compatible)
      </label>
      <label class="radio-label">
        <input name="keyType" value="EC" type="radio" <?= ( $certificate["valid"] && $certificate["keyType"] === "EC" ) ? "checked" : "" ?>> EC (Efficient)
      </label>
    </div>
  </div>

  <div class="button-grid">
    <button name="action" value="acquireandinstall" type="submit" class="full-width">Acquire & Install to cPanel</button>
    <button name="action" value="acquire" type="submit">Acquire Certificate</button>
    <button name="action" value="install" type="submit">Install into cPanel</button>
    <button name="action" value="test" type="submit" class="full-width">Run Staging Test</button>
  </div>
  </form>
<?php endif; ?>
</main>

<footer>
<ul>
  <li><a href="https://letsencrypt.org/donate/" target="_blank">Support Let's Encrypt</a></li>
  <li>&copy; 2021-2026 Griffin Software &bull; Secure SSL Manager</li>
</ul>
</footer>

<div id="wait"><div id="hourglass">&#x23F3;</div></div>
</body>
</html>