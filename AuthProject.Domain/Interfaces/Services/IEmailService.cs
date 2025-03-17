using AuthProject.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Interfaces.Services
{
    public interface IEmailService
    {
        Task<Result> SendEmailConfirmationAsync(string email, string username, string token);
        Task<Result> SendPasswordResetAsync(string email, string username, string token);
    }
}
