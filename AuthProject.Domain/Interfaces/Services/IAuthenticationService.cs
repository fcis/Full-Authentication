using AuthProject.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Services
{
    public interface IAuthenticationService
    {
        Task<Result<TAuthResult>> RegisterAsync<TRegister, TAuthResult>(TRegister model);
        Task<Result<TAuthResult>> LoginAsync<TLogin, TAuthResult>(TLogin model);
        Task<Result> ConfirmEmailAsync<TConfirmEmail>(TConfirmEmail model);
        Task<Result<TAuthResult>> RefreshTokenAsync<TRefreshToken, TAuthResult>(TRefreshToken model, string ipAddress);
        Task<Result> RevokeTokenAsync(string token, string ipAddress);
    }
}
