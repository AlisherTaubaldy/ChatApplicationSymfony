<?php

namespace App\Controller;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

#[Route('/user')]
final class AuthController extends AbstractController
{
    #[Route('/', name: 'app_index')]
    public function index(): Response
    {
        return $this->render('auth/index.html.twig', [
            'controller_name' => 'AuthController',
        ]);
    }

    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $passwordHasher,
        EntityManagerInterface $entityManager
    ): Response
    {
        if($request->isMethod('POST')){
            $data = $request->request->all();

            if(empty($data['name']) && empty($data['email']) && empty($data['password'])){
                $this->addFlash('error', 'All fields are required.');
                return $this->redirectToRoute('app_register');
            }

            $existingUser = $entityManager->getRepository(User::class)->findOneBy(['email' => $data['email']]);

            if($existingUser){
                $this->addFlash('error', 'Email already in use');
                return $this->redirectToRoute('app_register');
            }

            $user = new User();

            $user->setName($data['name']);
            $user->setEmail($data['email']);
            $user->setPassword($passwordHasher->hashPassword($user, $data['password']));

            $entityManager->persist($user);
            $entityManager->flush();

            $this->addFlash('success', 'Registration successful! You can now log in.');
            return $this->redirectToRoute('app_home');
        }

        return $this->render('auth/register.html.twig');
    }

    #[Route('/login', name: 'app_login', methods: 'GET, POST')]
    public function login(AuthenticationUtils $authenticationUtils, SessionInterface $session):Response
    {
        $error = $session->getFlashBag()->get('error')[0] ?? null;

        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('auth/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

}
