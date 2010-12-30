class EsapiException < StandardError end

class UserPertinentException < EsapiException
  attr_reader :user_msg
  def initialize user_msg
    @user_msg = user_msg
  end
end





