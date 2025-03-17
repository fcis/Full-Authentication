using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthProject.Domain.Exceptions
{
    public class InvalidTokenException : DomainException
    {
        public InvalidTokenException()
            : base("The token is invalid or has expired.") { }
    }
}
