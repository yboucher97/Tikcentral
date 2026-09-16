"""Tikcentral production ASGI entrypoint.

Keeps deployment-specific compatibility fixes and lightweight UI enhancements
separate from the core application.
"""

from starlette.responses import Response

from app import portal

_original_build_routeros_script = portal.build_routeros_script


def build_routeros_script_scoped(site_name: str, token: str) -> str:
    """Return enrollment script as one RouterOS local scope.

    RouterOS treats each line pasted at the terminal as a separate local scope.
    The enrollment generator relies on :local variables across many lines, so the
    entire body must be enclosed in one { ... } block.
    """
    script = _original_build_routeros_script(site_name, token)
    lines = script.splitlines()
    if len(lines) < 3:
        return "{\n" + script + "\n}"
    return "\n".join(lines[:2] + ["{"] + lines[2:] + ["}"])


portal.build_routeros_script = build_routeros_script_scoped
app = portal.app


ROUTER_COPY_UI = r'''
<style>
.router-row td[data-copyable="1"] { cursor: copy; transition: background .12s ease, outline .12s ease; }
.router-row td[data-copyable="1"]:hover { background: #18243d; outline: 1px solid #395182; outline-offset: -1px; }
.router-row td.copy-ok { background: #173427 !important; outline: 1px solid #31734f !important; outline-offset: -1px; }
#copyToast { position: fixed; right: 22px; bottom: 22px; z-index: 9999; background: #121a2d; color: #ecf2ff; border: 1px solid #395182; border-radius: 9px; padding: 10px 14px; box-shadow: 0 8px 30px rgba(0,0,0,.35); opacity: 0; transform: translateY(8px); pointer-events: none; transition: opacity .16s ease, transform .16s ease; }
#copyToast.show { opacity: 1; transform: translateY(0); }
</style>
<div id="copyToast">Copied</div>
<script>
(function(){
  const toast=document.getElementById('copyToast');
  let toastTimer;
  function showToast(value){
    toast.textContent='Copied: '+value;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer=setTimeout(()=>toast.classList.remove('show'),1400);
  }
  async function copyText(value, cell){
    if(!value || value==='-') return;
    try { await navigator.clipboard.writeText(value); }
    catch(e){
      const ta=document.createElement('textarea');
      ta.value=value; ta.style.position='fixed'; ta.style.opacity='0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    cell.classList.add('copy-ok');
    setTimeout(()=>cell.classList.remove('copy-ok'),650);
    showToast(value);
  }
  document.querySelectorAll('.router-row td').forEach((cell)=>{
    cell.dataset.copyable='1';
    cell.title='Click to copy';
    cell.addEventListener('click',()=>copyText(cell.innerText.trim(),cell));
  });
})();
</script>
'''


@app.middleware("http")
async def router_copy_middleware(request, call_next):
    response = await call_next(request)
    if request.url.path != "/routers":
        return response
    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return response
    body = b"".join([chunk async for chunk in response.body_iterator])
    text = body.decode("utf-8", "replace")
    if "</body>" in text:
        text = text.replace("</body>", ROUTER_COPY_UI + "</body>", 1)
    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(
        content=text,
        status_code=response.status_code,
        headers=headers,
        media_type="text/html",
        background=response.background,
    )
