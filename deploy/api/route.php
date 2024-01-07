<?php

$app->get('/api/hello/{name}', 'hello');

$app->options('/api/catalogue', 'optionsCatalogue');

// API Nécessitant un Jwt valide
$app->get('/api/catalogue/{filtre}', 'getSearchCatalogue');

// API Nécessitant un Jwt valide
$app->get('/api/catalogue', 'getCatalogue');

$app->options('/api/utilisateur', 'optionsUtilisateur');

// API Nécessitant un Jwt valide
$app->get('/api/utilisateur', 'getUtilisateur');

$app->post('/api/utilisateur/signup', 'getSignup');

// APi d'authentification générant un JWT
$app->post('/api/utilisateur/login', 'postLogin');
