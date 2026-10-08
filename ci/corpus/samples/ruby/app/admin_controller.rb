# frozen_string_literal: true

class AdminController < ApplicationController
  before_action :authenticate_admin!

  def index
    @users = User.order(:created_at).limit(50)
  end

  def show
    @user = User.find(params[:id])
  end

  private

  def authenticate_admin!
    head :forbidden unless current_user&.admin?
  end
end
