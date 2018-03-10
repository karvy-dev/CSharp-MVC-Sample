using AadhaarPortal.Models;
using My.Library.Crypto;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace AadhaarPortal.Controllers
{
    public class AuthRequestModel
    {
        public string Id { get; set; }
        public string Signature { get; set; }
        public string MobileNo { get; set; }
        public string Email { get; set; }
    }

    public class TestController : Controller
    {

        public ActionResult Index()
        {
            return RedirectToAction("Start");
        }

        public ActionResult Start()
        {
            return View();
        }

        [HttpPost]
        public ActionResult Start(AuthRequestModel m)
        {
            if (!ModelState.IsValid)
            {
                return View(m);
            }

            var csp = PkiHelper.RsaCSPFromFile(AppDomain.CurrentDomain.BaseDirectory + "\\private.pfx", "1");

            m.Signature = PkiHelper.SignSha1Base64String(csp, m.Id);

            TempData["AuthRequestModel"] = m;

            return RedirectToAction("Send");
        }

        public ActionResult Send()
        {
            var m = TempData["AuthRequestModel"] as AuthRequestModel;

            if (m == null || string.IsNullOrWhiteSpace(m.Signature))
            {
                return RedirectToAction("Start");
            }

            return View(m);
        }

        public ActionResult Reply()
        {
            return RedirectToAction("Start");
        }


        [HttpPost]
        public ActionResult Reply(ReturnModel model)
        {
            if (model.ResponseCode == "0")
            {
                var csp = PkiHelper.RsaCSPFromFile(AppDomain.CurrentDomain.BaseDirectory + "\\private.pfx", "1");
                var key = PkiHelper.DecryptOaepFromBase64String(csp, model.key);
                var iv = Convert.FromBase64String(model.iv);

                var json = AesHelper.DecryptFromBase64String(model.data, key, iv);

                var data = JsonConvert.DeserializeObject<DataBlock>(json);

                TempData["Result"] = new ReplyViewModel
                {
                    reply = model,
                    data = data,
                };

                TempData["Photo"] = data.picture;


            }
            else
            {
                TempData["Result"] = new ReplyViewModel
                {
                    reply = model,
                };

            }

            return RedirectToAction("Status");


        }

        public ActionResult Picture()
        {
            var pic = TempData["Photo"] as string;
            if (pic == null)
            {
                return null;
            }

            var picture = Convert.FromBase64String(pic);
            return File(picture, "image/jpg");

        }

        public ActionResult Status()
        {
            var m = TempData["Result"] as ReplyViewModel;

            if (m == null)
            {
                return RedirectToAction("Start");
            }

            return View(m);
        }



    }

    public class ReplyViewModel
    {
        public ReturnModel reply { get; set; }
        public DataBlock data { get; set; }
    }

    public class ReturnModel
    {
        public string Id { get; set; }
        public string ResponseCode { get; set; }
        public string Reason { get; set; }

        public string ts { get; set; }
        public string key { get; set; }
        public string iv { get; set; }
        public string data { get; set; }

    }

    public class DataBlock
    {
        public string picture { get; set; }

        public string name { get; set; }

        public string dob { get; set; }
        public string gender { get; set; }


        public string careOf { get; set; }
        public string buildingName { get; set; }
        public string landMark { get; set; }
        public string locality { get; set; }

        public string street { get; set; }
        public string village { get; set; }
        public string subDistrict { get; set; }

        public string district { get; set; }
        public string districtName { get; set; }
        public string state { get; set; }
        public string country { get; set; }

        public string pinCode { get; set; }
        public string postOffice { get; set; }


    }


}