<?php

namespace App\Security\Voter;

use App\Entity\Usuario;
use App\Security\UserProvider;
use Novosga\Dto\InstalledModule;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

final class ModuleAccessVoter extends Voter
{
    private const VIEW = 'view';

    protected function supports(string $attribute, mixed $subject): bool
    {
        dump($attribute, $subject);
        return in_array($attribute, [self::VIEW]) && $subject instanceof InstalledModule;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof Usuario || !$subject instanceof InstalledModule) {
            return false;
        }

        $roleName = UserProvider::roleName($subject->key);

        return $user->isAdmin() || in_array($roleName, $user->getRoles());
    }
}
