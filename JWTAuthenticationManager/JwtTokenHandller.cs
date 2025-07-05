using JWTAuthenticationManager.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthenticationManager
{
    public class JwtTokenHandller
    {
        public const string jWT_SECURITY_KEY = "ASDLKFJASLDPOADSPXCLSAOIMDCSWPDLLDVFSPLV";
        private const int JWT_tOKEN_VALIDATY_MINS = 20;
        private readonly List<UsersAcount> _usersAcount;
        public JwtTokenHandller()
        {
            _usersAcount = new List<UsersAcount>()
            {
                new UsersAcount() { UserName = "Firest U", Password = "Password1", Role = "Administrator" },
                new UsersAcount() { UserName = "Firest U", Password = "Password2", Role = "user" },
                new UsersAcount() { UserName = "Firest U", Password = "Password3", Role = "Writer" },


            };
        }

        public AuthenticationResponse? GenerateJwtToken(AuthenticationRequest request)
        {
            if (string.IsNullOrEmpty(request.UserName) || string.IsNullOrEmpty(request.Password))
                return null;
            //Validate user
            var user = _usersAcount.Where(x => x.UserName == request.UserName && x.Password == request.Password).FirstOrDefault();
            if (user == null)
                return null;
            var tokenExpireyTimeStamp = DateTime.Now.AddMinutes(JWT_tOKEN_VALIDATY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(jWT_SECURITY_KEY);
            var claimsIdentity = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Name,request.UserName),
                new Claim(ClaimTypes.Role,user.Role)
            });
            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature);
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpireyTimeStamp,
                SigningCredentials = signingCredentials
            };
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);
            var response = new AuthenticationResponse()
            {
                UserName = user.UserName,
                ExpiresIn = (int)tokenExpireyTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                JwtToken = token
            };
            return response;
        }
    }
}
