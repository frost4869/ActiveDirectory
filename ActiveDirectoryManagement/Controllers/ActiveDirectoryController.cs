using ActiveDirectoryManagement.Common;
using ActiveDirectoryManagement.Models;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Principal;
using System.Web.Mvc;


namespace ActiveDirectoryManagement.Controllers
{
    public class ActiveDirectoryController : Controller
    {
        private const int ERROR_LOGON_FAILURE = 0x31;
        // GET: ActiveDirectory
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        public JsonResult UpdatePassword(string newpassword, string confirmpassword)
        {
            var curUser = Session["user"] as User;
            var domain = Session["domain"] as string;

            if (curUser != null && !string.IsNullOrEmpty(domain))
            {
                if (string.IsNullOrEmpty(newpassword) || string.IsNullOrEmpty(confirmpassword))
                {
                    return Json(new
                    {
                        success = false,
                        message = "Please enter New Password"
                    });
                }

                if (newpassword.Equals(confirmpassword))
                {
                    try
                    {
                        using (var context = new PrincipalContext(ContextType.Domain, domain, Assets.AdminUsername, Assets.AdminPassword))
                        {
                            using (var user = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, curUser.Username))
                            {
                                user.SetPassword(newpassword);
                                user.Save();

                                Session.RemoveAll();
                                return Json(new
                                {
                                    success = true,
                                    message = "Password Updated. Login again"
                                });
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        return Json(new
                        {
                            success = false,
                            message = ex.Message,
                            exception = ex
                        });
                    }
                }
                else
                {
                    return Json(new
                    {
                        success = false,
                        message = "Confirm Password Mismatched"
                    });
                }
            }
            else
            {
                return Json(new
                {
                    success = false,
                    type = "Login",
                    message = "Please Login"
                });
            }
        }

        public JsonResult Validation(User user, string domain)
        {
            NetworkCredential credentials = new NetworkCredential(user.Username, user.Password, domain);

            LdapDirectoryIdentifier id = new LdapDirectoryIdentifier(domain);

            using (LdapConnection connection = new LdapConnection(id, credentials, AuthType.Kerberos))
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;

                try
                {
                    connection.Bind();
                }
                catch (LdapException lEx)
                {
                    if (ERROR_LOGON_FAILURE == lEx.ErrorCode)
                    {
                        return Json(new
                        {
                            success = false,
                            message = "Wrong Username or Password",
                        });
                    }
                    throw;
                }
            }

            Session["domain"] = domain;
            Session["user"] = user;
            return Json(new
            {
                success = true,
            });
        }

        public ActionResult Logout()
        {
            Session.RemoveAll();
            return RedirectToAction("Index");
        }
    }
}