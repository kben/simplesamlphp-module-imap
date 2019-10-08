<?php

//use SimpleSAML\Module\imapauth\Auth\Source\imap\imap_rcube;

namespace SimpleSAML\Module\imapauth\Auth\Source;

/**
 * Simple IMAP authentication source
 *
 * This class is an example authentication source which authenticates an user
 * against an IMAP Server.
 *
 * @package SimpleSAMLphp
 */

class IMAP extends \SimpleSAML\Module\core\Auth\UserPassBase
{
    /**
     * server to connect
     */
    private $server;

    /**
     * port to connect
     */
    private $port;

    /**
     * allowed domain
     */
    private $domain;

    /**
     * admin users
     */
    private $admin;

    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config)
    {
        assert(is_array($info));
        assert(is_array($config));

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Make sure that all required parameters are present.
        foreach (['server', 'port', 'domain', 'admin'] as $param) {
            if (!array_key_exists($param, $config)) {
                throw new \Exception('Missing required attribute \''.$param.
                    '\' for authentication source '.$this->authId);
            }

            if (!is_string($config[$param]) && !is_array($config[$param])) {
                throw new \Exception('Expected parameter \''.$param.
                    '\' for authentication source '.$this->authId.
                    ' to be a string. Instead it was: '.
                    var_export($config[$param], true));
            }
        }

        $this->server = $config['server'];
        $this->port = $config['port'];
        $this->domain = $config['domain'];
        $this->admin = $config['admin'];
    }



    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login($username, $password)
    {
        // Replace escaped @ symbol in uid (which is a mail address)
        // but only if there is no @ symbol and if there is a %40 inside the uid
        if (!(strpos($username, '@') !== false) && (strpos($username, '%40') !== false)) {
                $username = str_replace("%40","@",$username);
        }

	$username = strtolower($username);

        $rcube = new imap_rcube();
        $params = ["port"=>$this->port, "timeout"=>10];
	$arr = explode("@", $username);
	if (count($arr) != 2) {
	    \SimpleSAML\Logger::error('imapauth:'.$this->authId.
                ': Username not valid.');
	    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
	}
	if (strtolower($arr[1]) != strtolower($this->domain)) {
	    \SimpleSAML\Logger::error('imapauth:'.$this->authId.
                ': Username not valid.');
	    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
	}

        $params["ssl_mode"] = null; // $this->sslmode ? $this->sslmode : null;
        $params["force_caps"] = false;
        $canconnect = $rcube->connect(
                                $this->server,
                                $username,
                                $password,
                                $params
        );

        if(!$canconnect) {
	    \SimpleSAML\Logger::error('imapauth:'.$this->authId.
                ': Cannot connect to server.');
	    throw new \SimpleSAML\Error\Error('WRONGUSERPASS');
        }

        $attributes = [];
	$attributes['name'][] = str_replace(".", " ", $arr[0]);
	$nam = explode(".", $arr[0]);
	$number_nam = count($nam);
	if ($number_nam > 0) $attributes['firstname'][] = $nam[0];
	if ($number_nam > 1) $attributes['lastname'][] = $nam[1];
	$attributes['domain'][] = $arr[1];
	$attributes['email'][] = $username;
	$attributes['admin'][] = in_array($username, $this->admin);

        \SimpleSAML\Logger::info('imapauth:'.$this->authId.': Attributes: '.
            implode(',', array_keys($attributes)));
        $rcube->closeConnection();
        return $attributes;
    }
}
