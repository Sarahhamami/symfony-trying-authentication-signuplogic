<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
class SecurityController extends AbstractController
{
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils, Security $security): Response
    {
        /*if ($this->getUser()) {
            return $this->redirectToRoute('app_profile');
        }*/

        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        //         if ($error)
        //         dd($error);

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        if ($security->isGranted('IS_AUTHENTICATED_FULLY')) {

            return $this->render('base.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
        } else {
            // Return the existing response when the user is not authenticated
            return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
        }
    }

    #[Route(path: '/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }

    // Connect with Google 
    #[Route('/connect/google', name: 'connect_google_start')]
    public function connectAction(ClientRegistry $clientRegistry)
    {
        // will redirect to Facebook!
        return $clientRegistry->getClient('google')->redirect(
            ['openid', 'email', 'profile'], // The scopes
            ['http://127.0.0.1:8000/connect/google/check'] // The redirect URL after successful authentication
        );
        
    }

    #[Route('/connect/google/check', name: 'connect_google_check')]
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {
        if (!$this->getUser()){
            return new JsonResponse(array('status'=> false, 'message'=> "User not found!"));
        }else{
            return $this->redirectToRoute('app_admin');
        }
        }
    
}
