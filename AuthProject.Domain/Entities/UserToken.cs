using AuthProject.Domain.Common;
using AuthProject.Domain.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Entities
{
    public class UserToken : BaseEntity
    {
        public Guid UserId { get; set; }
        public TokenType TokenType { get; set; }
        public string Token { get; set; }
        public DateTime ExpiryDate { get; set; }
        public bool IsUsed { get; set; }
    }
}
