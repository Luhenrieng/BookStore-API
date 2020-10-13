using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BookStore_UI.Models
{
    public class TokenResponse
    {
        //public string Token { get; set; }


        public string result { get; set; }
        public int id { get; set; }
        public string exception { get; set; }
        public bool isCanceled { get; set; }
        public bool isCompleted { get; set; }
        public bool isCompletedSuccessfully { get; set; }
        public int creationOptions { get; set; }
        public object asyncState { get; set; }
        public bool isFaulted { get; set; }
        public TokenResponse token { get; set; }
    }
}
