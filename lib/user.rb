# Author::    Loren Sands-Ramshaw  (mailto:lorensr@gmail.com)
# Copyright:: Copyright (c) 2010 The OWASP Foundation
# License::   New BSD License

# The User represents an application user or user account. There is quite a lot of information that an
# application must store for each user in order to enforce security properly. There are also many rules that govern
# authentication and identity management.
#
# A user account can be in one of several states. When first created, a User should be disabled, not expired, and
# unlocked. To start using the account, an administrator should enable the account. The account can be locked for a
# number of reasons, most commonly because they have failed login for too many times. Finally, the account can expire
# after the expiration date has been reached. The User must be enabled, not expired, and unlocked in order to pass
# authentication.


#log add_role ; vars changed: enabled, name, id, expiration_time, last_failed_login_time, last_login_time, last_password_change_time, alias

class User
  attr_reader(
              :csrf_token,
              :locked,
              :logged_in,
              :events
              )

  attr_accessor(
                :name,
                :disabled,
                :failed_login_count,
                :sessions,
                :roles,
                :id,
                :expiration_time,
                :last_failed_login_time,
                :last_login_time,
                :last_host_address,
                :last_password_change_time,
                :alias,
                :locale
                )

  def initialize name
    @name = name
    @id = rand 2**64-1 while Auth.user(@id) || @id == 0
    @failed_login_count = 0
  end

  def add_role role
    #validate
    @roles << role
  end

  def change_password old, new1, new2
    Auth.change_password @id, old, new1, new2
  end

  def expired
    @expiration_time <= now
  end

  def lock
    @locked = true
  end

  def unlock
    @locked = false
  end

  def login password
    # allowed to login?
    {:disabled, :locked, :expired}.each do |check|
      if eval("@" + check.to_s)
        @last_failed_login_time = now
        @failed_login_count += 1
        eval("raise Account" + check.to_s.capitalize + ", \"Error: account is " + check.to_s + ".\", " + id.to_s)
      end
    end

    if Auth.verify_password(id, password)
      @logged_in = true
      # ESAPI.httpUtilities().changeSessionIdentifier( ESAPI.currentRequest() );
      Auth.set_user self
      @last_login_time = now
      @last_host_address = $request.host_address
      log SUCCESS
    else
      @logged_in = false
      @last_failed_login_time = now
      @failed_login_count += 1
      if @failed_login_count = ALLOWED_LOGIN_ATTEMPTS
        lock
        raise MaxLoginAttempts
      else
        raise WrongPassword
      end
    end
  end

  def logout
    @logged_in = false
    $session.kill
    @sessions.delete $session
    Auth.set_user nil
    log SUCCESS
  end

  def last_host_address=(current_host)
    if @last_host_address && @last_host_address != current_host
      raise HostChange
    end
    @last_host_address = current_host    
  end

  def to_s
    "USER: " + @name
  end
end
