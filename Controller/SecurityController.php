<?php

/*
 * This file is part of the FOSUserBundle package.
 *
 * (c) FriendsOfSymfony <http://friendsofsymfony.github.com/>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FOS\UserBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use FOS\UserBundle\FOSUserEvents;
use FOS\UserBundle\Event\FormEvent;
use FOS\UserBundle\Event\GetResponseUserEvent;
use Symfony\Component\Security\Core\SecurityContextInterface;

class SecurityController extends Controller
{
    /**
     * @param Request $request
     *
     * @return Response
     */



    public function browser($info){

        $u_agent = $_SERVER['HTTP_USER_AGENT'];
        $bname = 'Unknown';
        $platform = 'Unknown';
        $version= "";

        //First get the platform?
        if (preg_match('/linux/i', $u_agent)) {
            $platform = 'linux';
        }
        elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
            $platform = 'mac';
        }
        elseif (preg_match('/windows|win32/i', $u_agent)) {
            $platform = 'windows';
        }

        // Next get the name of the useragent yes seperately and for good reason
        $ub = null;
        if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent))
        {
            $bname = 'Internet Explorer';
            $ub = "MSIE";
        }
        elseif(preg_match('/Firefox/i',$u_agent))
        {
            $bname = 'Mozilla Firefox';
            $ub = "Firefox";
        }
        elseif(preg_match('/OPR/i',$u_agent))
        {
            $bname = 'Opera';
            $ub = "Opera";
        }
        elseif(preg_match('/Chrome/i',$u_agent))
        {
            $bname = 'Google Chrome';
            $ub = "Chrome";
        }
        elseif(preg_match('/Safari/i',$u_agent))
        {
            $bname = 'Apple Safari';
            $ub = "Safari";
        }
        elseif(preg_match('/Netscape/i',$u_agent))
        {
            $bname = 'Netscape';
            $ub = "Netscape";
        }elseif(preg_match('/Mozilla/i',$u_agent))
        {
            $bname = 'Mozilla Firefox';
            $ub = "Firefox";
        }

        // finally get the correct version number
        $known = array('Version', $ub, 'other');
        $pattern = '#(?<browser>' . join('|', $known) .
            ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
        if (!preg_match_all($pattern, $u_agent, $matches)) {
            // we have no matching number just continue
        }
        if(is_array($matches['browser'])){
            // see how many we have
            $i = count($matches['browser']);
        }else{
            $i = 1;
        }
        if ($i != 1) {
            
            //we will have two since we are not using 'other' argument yet
            //see if version is before or after the name
            if (strripos($u_agent,"Version") < strripos($u_agent,$ub)){
                $version= $matches['version'][0];
            }
            else {
               // $version= $matches['version'][1];
                    if(isset($matches['version'][1]))
                        $version= $matches['version'][1];
                    else
                        $version="";

            }
        }
        else {
            $version= $matches['version'][0];
        }

        // check if we have a number
        if ($version==null || $version=="") {$version="?";}


        if($info == 'u_agent'){
            return $u_agent;
        }
        if($info == 'bname'){
            return $bname;
        }
        if($info == 'version'){
            return $version;
        }
        if($info == 'platform'){
            return $platform;
        }
        if($info == 'pattern'){
            return $pattern;
        }

    }
    public function loginAction(Request $request)
    {

        /** @var $session \Symfony\Component\HttpFoundation\Session\Session */
        $session = $request->getSession();

        $authErrorKey = Security::AUTHENTICATION_ERROR;
        $lastUsernameKey = Security::LAST_USERNAME;

        // get the error if any (works with forward and redirect -- see below)
        if ($request->attributes->has($authErrorKey)) {

            $error = $request->attributes->get($authErrorKey);
        } elseif (null !== $session && $session->has($authErrorKey)) {
            $error = $session->get($authErrorKey);
            $session->remove($authErrorKey);
        } else {
            $error = null;
        }

        if (!$error instanceof AuthenticationException) {
            $error = null; // The value does not come from the security component.
        }

        // last username entered by the user
        $lastUsername = (null === $session) ? '' : $session->get($lastUsernameKey);

        $csrfToken = $this->has('security.csrf.token_manager')
            ? $this->get('security.csrf.token_manager')->getToken('authenticate')->getValue()
            : null;

        $formFactory = $this->get('fos_user.registration.form.factory');
        $userManager = $this->get('fos_user.user_manager');
        $dispatcher = $this->get('event_dispatcher');


        $user = $userManager->createUser();

        $user->setEnabled(true);
        $user->setUserPermission('Član');

        $event = new GetResponseUserEvent($user, $request);
        $dispatcher->dispatch(FOSUserEvents::REGISTRATION_INITIALIZE, $event);

        if (null !== $event->getResponse()) {
            return $event->getResponse();
        }

        $form = $formFactory->createForm();
        $form->setData($user);

        $form->handleRequest($request);
        $userOutfit = 0;
        $em = $this->getDoctrine()->getManager();
        if($this->container->get('security.token_storage')->getToken()){
            if($loggedinuser = $this->container->get('security.token_storage')->getToken()->getUser()){
                if ($loggedinuser != 'anon.') {

                    $created = $em->getRepository('WebsiteCatalogueBundle:Outfit')->findOneBy(array('users' => $loggedinuser));
                    if($created != NULL) {
                        $userOutfit = 1;

                    }

                }
            }
        }
        $nllabeloverall = 0;
        $nllabeloveralltext = false;
        $newsletter = $em->getRepository('WebsiteDefaultBundle:CmsSettings')->findOneBy(array("title" => "nllabeloverall"), array());
        if($newsletter && $newsletter->getParams()== 1){
            $nllabeloverall = 1;
            $nllabeloveralltext = $em->getRepository('WebsiteDefaultBundle:CmsSettings')->findOneBy(array("title" => "nllabeloveralltext"), array());
            if($nllabeloveralltext){
                $nllabeloveralltext = $nllabeloveralltext->getParams();
            }
        }



        if (strpos($this->browser('u_agent'), 'FB') !== false) {
            $browser = 1;
        } else {

            if (strpos($this->browser('u_agent'), 'Pinterest') !== false) {
                $browser = 1;
            } else {
                $browser = 0;
            }
        }
        $browser = 1;

        return $this->renderLogin(array(
            'user_outfits' => $userOutfit,
            'last_username' => $lastUsername,
            'error' => $error,
            'form' => $form->createView(),
            'csrf_token' => $csrfToken,
            'nllabeloverall' => $nllabeloverall,
            'nllabeloveralltext' => $nllabeloveralltext,
            'browser' => $browser
        ));
    }

    /**
     * Renders the login template with the given parameters. Overwrite this function in
     * an extended controller to provide additional data for the login template.
     *
     * @param array $data
     *
     * @return Response
     */
    protected function renderLogin(array $data)
    {
        return $this->render('@FOSUser/Security/login.html.twig', $data);
    }

    public function checkAction()
    {

        throw new \RuntimeException('You must configure the check path to be handled by the firewall using form_login in your security firewall configuration.');
    }

    public function logoutAction()
    {
        throw new \RuntimeException('You must activate the logout in your security firewall configuration.');
    }
}
