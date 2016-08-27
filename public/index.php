<?php

session_cache_limiter(false);
session_start();

error_reporting(-1);
ini_set('error_reporting', E_ALL);

require '../vendor/autoload.php';

$app = new \Slim\Slim();
$app->config(array(
    'debug' 			=> true,
    'view' 				=> new \Slim\Views\Twig(),
    'templates.path' 	=> '../app/templates',
    'hashing.algorithm' => 'sha512',
    'key'				=> '../key.pem'
));

$view = $app->view();
$view->parserExtensions = array(
    new \Slim\Views\TwigExtension(),
);

$rsa = new Crypt_RSA();
$rsa->loadKey(file_get_contents($app->config('key')));

// urlFor
$app->view->setData('urlFor', function($name,  $params = array()) use ($app) {
	return $app->urlFor($name, $params);
});

$app->get('/', function() use ($app) {
	$app->render('index.twig');
})->name('home');


$app->map('/stamp', function() use ($app, $rsa) {

	if($app->request()->isPost()) {
		if(!empty($_FILES['file']) && !$_FILES['file']['error']) {
			
			$hash = hash_file($app->config('hashing.algorithm'), $_FILES['file']['tmp_name']);
			$beacon = simplexml_load_string(file_get_contents('https://beacon.nist.gov/rest/record/last'));
			if($hash && $beacon) {
				$rsa->loadKey($rsa->getPrivateKey());
				$signature = $rsa->sign($hash . $beacon->timeStamp . $beacon->seedValue);
				$app->response->headers->set('Content-Type', 'text/plain');
				$app->response->headers->set('Content-Disposition', 'attachment; filename=timecert.tf');
				echo $beacon->timeStamp . "\n";
				echo $signature;
				$app->stop();
			}
		}
	}
	$app->render('stamp.twig');

})->via('GET', 'POST')->name('stamp');


$app->map('/verify', function() use ($app, $rsa) {
	$data = array();

	if($app->request()->isPost()) {
		$valid = false;
		if(!empty($_FILES['file']) && !$_FILES['file']['error']
			&& !empty($_FILES['certificate']) && !$_FILES['certificate']['error']) {
			
			$hash = hash_file($app->config('hashing.algorithm'), $_FILES['file']['tmp_name']);

			$certificate = file_get_contents($_FILES['certificate']['tmp_name']);
			$certificate = explode("\n", $certificate, 2);

			if(count($certificate) == 2) {
				$certificate[0] = filter_var($certificate[0], FILTER_SANITIZE_NUMBER_INT);
				$beacon = simplexml_load_string(file_get_contents('https://beacon.nist.gov/rest/record/' . $certificate[0]));

				if($beacon) {
					$rsa->loadKey($rsa->getPublicKey());
					$valid = $rsa->verify($hash . $beacon->timeStamp . $beacon->seedValue, $certificate[1]);

					if($valid) {
						$data['cert_date'] = date("c", (int) $beacon->timeStamp);
					}
				}
			}
		}

		$data['valid'] = $valid;
	}

	$app->render('verify.twig', $data);

})->via('GET', 'POST')->name('verify');


$app->run();