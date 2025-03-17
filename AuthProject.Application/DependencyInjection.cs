using AuthProject.Application.Services;
using AuthProject.Application.Validators;
using AuthProject.Domain.Interfaces.Services;
using FluentValidation.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Application
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddApplication(this IServiceCollection services)
        {
            // Register FluentValidation
            services.AddFluentValidationAutoValidation();

            // Register Validators
            services.AddScoped<RegisterDtoValidator>();
            services.AddScoped<LoginDtoValidator>();
            services.AddScoped<ForgotPasswordDtoValidator>();
            services.AddScoped<ResetPasswordDtoValidator>();

            // Register Services
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddScoped<IPasswordService, PasswordService>();

            return services;
        }
    }
}
