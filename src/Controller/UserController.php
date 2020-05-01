<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Security\Guard\GuardAuthenticatorHandler;
use App\Security\MainAuthenticator;
use Symfony\Component\HttpFoundation\Request;
use App\Entity\User;
use App\Form\RegistrationFormType;
use Symfony\Component\Security\Core\Security;

class UserController extends AbstractController
{
    private $user; 

    public function __construct(Security $security) {
        $this->user         = $security->getUser();
    }
    /**
     * @Route("/user", name="user")
     */
    public function index()
    {
        return $this->render('user/index.html.twig', [
            'controller_name' => 'UserController',
        ]);
    }


    /**
     * @Route("/login", name="user_login")
     */
    public function loginPage(AuthenticationUtils $authenticationUtils) : Response
    {
    	if ($this->getUser()) {
            return $this->redirectToRoute('user');
        }

    	$data['page'] = 'login';

    	// get the login error if there is one
        $data['error'] = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $data['last_username'] = $authenticationUtils->getLastUsername();

        return $this->render('user/login.html.twig', $data);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }


    /**
     * @Route("/register", name="user_register")
     */
    public function registerPage(Request $request, UserPasswordEncoderInterface $passwordEncoder, GuardAuthenticatorHandler $guardHandler, MainAuthenticator $authenticator)
    {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            // encode the plain password
            $user->setPassword(
                $passwordEncoder->encodePassword(
                    $user,
                    $form->get('password')->getData()
                )
            );
            $user->setRoles(["ROLE_USER"]);
            $entityManager = $this->getDoctrine()->getManager();
            $entityManager->persist($user);
            $entityManager->flush();

            // do anything else you need here, like send an email

            return $guardHandler->authenticateUserAndHandleSuccess(
                $user,
                $request,
                $authenticator,
                'main' // firewall name in security.yaml
            );
        }
        $data['page'] = 'register';
        $data['registrationForm'] = $form->createView();

        return $this->render('user/register.html.twig', $data);
    }


    /**
     * @Route("/dashboard", name="user_dashboard")
     */
    public function dashboardPage()
    {
    	$data['page'] = 'dashboard';

        return new Response("CONNECTED...");
    }
}
