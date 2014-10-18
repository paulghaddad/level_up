class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  ensure_security_headers(
    x_frame_options: "DENY",
    x_content_type_options: "nosniff",
    x_xss_protection: { value: 1, mode: false },
    csp: false, # no cross-site scripting
    hsts: false, # ensure https
  )

  rescue_from CanCan::AccessDenied do |exception|
    redirect_to root_path, alert: exception.message
  end

  def current_user
    super || Guest.new
  end
  helper_method :current_user
end
