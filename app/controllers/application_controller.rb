class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
  before_filter :authenticate_user_from_token
  before_filter :miniprofiler
  before_filter :redirect_to_real_domain

  rescue_from CanCan::AccessDenied do |exception|
    redirect_to root_path, alert: exception.message
  end

  def current_user
    super || Guest.new
  end
  helper_method :current_user

  private

  def authenticate_user_from_token
    if user = User.from_token_auth(token_auth_params)
      sign_in user, store: false
    end
  end

  def token_auth_params
    params.permit(:auth_email, :auth_token)
  end

  def miniprofiler
    Rack::MiniProfiler.authorize_request if current_user.admin?
  end

  def redirect_to_real_domain
    return unless request.host =~ /herokuapp./
    redirect_to request.url.gsub(/herokuapp./, '')
  end

  def render_bad_response(message)
    render json: { success: false, error: message },
           status: :unprocessable_entity
  end
end
