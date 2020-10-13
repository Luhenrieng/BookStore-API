using Microsoft.JSInterop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace BookStore_UI.Service
{
    public class LocalStorage
    {
        private readonly IJSRuntime _jsRuntime;

        public LocalStorage(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        public async Task SetAsync<T>(string key, T value)
        {
            string jsVal = null;
            if (value != null)
                jsVal = JsonSerializer.Serialize(value);
            await _jsRuntime.InvokeVoidAsync("localStorage.setItem",
                new object[] { key, jsVal });
        }
        public async Task<T> GetAsync<T>(string key)
        {
            string val = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", key);
            if (val == null) return default;
            T result = JsonSerializer.Deserialize<T>(val);
            return result;
        }
        public async Task RemoveAsync(string key)
        {
            await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", key);
        }
        public async Task ClearAsync()
        {
            await _jsRuntime.InvokeVoidAsync("localStorage.clear");
        }
    }
}
