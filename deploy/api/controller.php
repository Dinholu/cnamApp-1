<?php

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;


function optionsCatalogue(Request $request, Response $response, $args)
{

	// Evite que le front demande une confirmation à chaque modification
	$response = $response->withHeader("Access-Control-Max-Age", 600);

	return addHeaders($response);
}

function hello(Request $request, Response $response, $args)
{
	$array = [];
	$array["nom"] = $args['name'];
	$response->getBody()->write(json_encode($array));
	return $response;
}

function getSearchCatalogue(Request $request, Response $response, $args)
{
	global $entityManager;
	$filtre = $args['filtre'];

	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $filtre)) {
		$response = $response->withStatus(500);
		return addHeaders($response);
	}

	$produitRepository = $entityManager->getRepository('Produits');

	$produits = $produitRepository->createQueryBuilder('p')
		->where('LOWER(p.nom) LIKE :filtre OR LOWER(p.description) LIKE :filtre')
		->setParameter('filtre', '%' . strtolower($filtre) . '%')
		->getQuery()
		->getResult();

	if ($produits) {
		$data = array();
		foreach ($produits as $produit) {
			$data[] = array(
				'id' => $produit->getId(),
				'nom' => $produit->getNom(),
				'img' => $produit->getImg(),
				'description' => $produit->getDescription(),
				'prix' => $produit->getPrix(),
				'categorie' => $produit->getCategorie()->getLabel(),
			);
		}
		$response = addHeaders($response);
		$response = createJwT($response);
		$response->getBody()->write(json_encode($data));
	} else {
		$response = $response->withStatus(404);
		$response->getBody()->write("Aucun produit trouvé pour le filtre '$filtre'.");
	}

	return addHeaders($response);
}


// API Nécessitant un Jwt valide
function getCatalogue(Request $request, Response $response, $args)
{
	global $entityManager;

	$payload = getJWTToken($request);
	$login  = $payload->userid;

	$utilisateurRepository = $entityManager->getRepository('Utilisateurs');
	$utilisateur = $utilisateurRepository->findOneBy(array('login' => $login));

	$produitRepository = $entityManager->getRepository('Produits');
	$produits = $produitRepository->findAll();

	$data = [];

	if ($utilisateur) {

		foreach ($produits as $produit) {
			$data[] = [
				'id' => $produit->getId(),
				'nom' => $produit->getNom(),
				'img' => $produit->getImg(),
				'description' => $produit->getDescription(),
				'prix' => $produit->getPrix(),
				'categorie' => $produit->getCategorie()->getLabel(),
			];
		}
	} else {
		$response = $response->withStatus(404);
	}

	$response->getBody()->write(json_encode($data));

	return addHeaders($response);
}

// API Nécessitant un Jwt valide
function getUtilisateur(Request $request, Response $response, $args)
{
	global $entityManager;

	$payload = getJWTToken($request);
	$login  = $payload->userid;

	$utilisateurRepository = $entityManager->getRepository('Utilisateurs');
	$utilisateur = $utilisateurRepository->findOneBy(array('login' => $login));
	if ($utilisateur) {
		$data = array('nom' => $utilisateur->getNom(), 'prenom' => $utilisateur->getPrenom());
		$response = addHeaders($response);
		$response = createJwT($response);
		$response->getBody()->write(json_encode($data));
	} else {
		$response = $response->withStatus(404);
	}

	return addHeaders($response);
}

function getSignup(Request $request, Response $response)
{
	global $entityManager;
	$err = false;
	$body = $request->getBody();
	$body = json_decode($body, true);
	$response = addHeaders($response);
	$response->getBody()->write(json_encode($body));

	$nom = $body['nom'] ?? "";
	$prenom = $body['prenom'] ?? "";
	$adresse = $body['adresse'] ?? "";
	$cp = $body['codepostal'] ?? "";
	$ville = $body['ville'] ?? "";
	$email = $body['email'] ?? "";
	$sexe = $body['sexe'] ?? "";
	$login = $body['login'] ?? "";
	$pass = $body['password'] ?? "";
	$tel = $body['telephone'] ?? "";

	// Validation des données
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $nom)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $prenom)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $adresse)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $cp)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $ville)) {
		$err = true;
	}
	if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $sexe)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $login)) {
		$err = true;
	}
	if (strlen($pass) < 8 || !preg_match('/[A-Z]/', $pass) || !preg_match('/[a-z]/', $pass) || !preg_match('/[0-9]/', $pass)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $tel)) {
		$err = true;
	}

	if (!$err) {
		$existingUser = $entityManager->getRepository(Utilisateurs::class)->findOneBy(['login' => $login]);

		if ($existingUser) {
			$response = $response->withStatus(409);
			$response->getBody()->write(json_encode(['message' => 'Le login est deja utilise. Veuillez en choisir un autre.']));
		} else {
			$hashedPassword = password_hash($pass, PASSWORD_DEFAULT);
			$user = new Utilisateurs();
			$user->setNom($nom);
			$user->setPrenom($prenom);
			$user->setAdresse($adresse);
			$user->setCodepostal($cp);
			$user->setVille($ville);
			$user->setEmail($email);
			$user->setSexe($sexe);
			$user->setLogin($login);
			$user->setPassword($hashedPassword);

			$entityManager->persist($user);
			$entityManager->flush();
			$response = createJwT($response);
			$response->getBody();
		}
	} else {
		$response = $response->withStatus(500);
	}

	return addHeaders($response);
}


// APi d'authentification générant un JWT
function postLogin(Request $request, Response $response, $args)
{
	global $entityManager;
	$err = false;
	$body = $request->getParsedBody();
	$login = $body['login'] ?? "";
	$pass = $body['password'] ?? "";

	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $login)) {
		$err = true;
	}
	if (!preg_match("/[a-zA-Z0-9]{1,20}/", $pass)) {
		$err = true;
	}
	if (!$err) {
		$utilisateurRepository = $entityManager->getRepository('Utilisateurs');
		// verifier le hash du mot de passe
		$utilisateur = $utilisateurRepository->findOneBy(array('login' => $login));
		if ($utilisateur && password_verify($pass, $utilisateur->getPassword())) {
			$response = addHeaders($response);
			$response = createJwT($response);
			$data = array('nom' => $utilisateur->getNom(), 'prenom' => $utilisateur->getPrenom());
			$response->getBody()->write(json_encode($data));
		} else {

			$response = $response->withStatus(403);
		}
	} else {
		$response = $response->withStatus(500);
	}

	return addHeaders($response);
}
