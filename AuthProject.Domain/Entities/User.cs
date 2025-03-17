using AuthProject.Domain.Common;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Entities
{
    public class User : BaseEntity
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool IsActive { get; set; }
        public int LoginAttempts { get; set; }
        public DateTime? LockoutEnd { get; set; }
        public DateTime? LastLogin { get; set; }
    }
}
