module Owasp_Esapi_Ruby
  alias :now :Time.now
  def raise(e, msg)
    #todo log (or in initialize of error?)
    Kernel.raise(e, msg, caller)
  end
end

