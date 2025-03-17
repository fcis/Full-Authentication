using AuthProject.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Services
{
    public interface IPasswordService
    {
        Task<Result> ForgotPasswordAsync<TForgotPassword>(TForgotPassword model);
        Task<Result> ResetPasswordAsync<TResetPassword>(TResetPassword model);
        string HashPassword(string password);
        bool VerifyPassword(string password, string passwordHash);
    }
}
