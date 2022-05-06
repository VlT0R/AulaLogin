using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Login.Controllers
{
    public class LoginController : Controller
    {
        private readonly Contexto db;
        public LoginController(Contexto contexto)
        {
            db = contexto;
        }
        public IActionResult Entrar()
        {
            return View();
        }
        [HttpPost]
        public async Task<ActionResult> Entrar(string login,string senha)
        {
            Entidades.Usuario usuariologado = db.USUARIOS.Where(a => a.Login == login && a.Senha == senha).FirstOrDefault();
            if (usuariologado == null)
            {
                TempData["erro"] = "usuario e senha invalido";
                return View();
            }

            var claims = new List<Claim>();

            claims.Add(
              new Claim(ClaimTypes.Name, usuariologado.Nome));
            claims.Add(
              new Claim(ClaimTypes.Sid, usuariologado.Id.ToString()));

            var userIdentity = new ClaimsIdentity(claims, "Acesso");

            ClaimsPrincipal principal = new ClaimsPrincipal(userIdentity);
            await HttpContext.SignInAsync("CookieAuthentication", principal, new AuthenticationProperties());

            return Redirect("/");
        }

        public async Task<IActionResult> Logoff()
        {
            await HttpContext.SignOutAsync("CookieAuthentication");
            ViewData["ReturnUrl"] = "/";
            return Redirect("/Login/Entrar");
        }

    }
}
