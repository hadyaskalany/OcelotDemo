using JWTAuthenticationManager;
using JWTAuthenticationManager.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtTokenHandller _jwtTokenHandller;
        public AccountController(JwtTokenHandller jwtTokenHandller)
        {
            _jwtTokenHandller = jwtTokenHandller;
        }

        [HttpPost]
        public ActionResult<AuthenticationResponse?> Authenticate([FromBody] AuthenticationRequest request)
        {
            var authenticationRespose = _jwtTokenHandller.GenerateJwtToken(request);
            if (authenticationRespose == null) return Unauthorized();

            return authenticationRespose;
        }



    }
}
