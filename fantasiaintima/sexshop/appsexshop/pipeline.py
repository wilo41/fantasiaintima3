# pipeline.py

def create_user_in_custom_table(backend, user, response, *args, **kwargs):
    from appsexshop.models import usuario, roles
    from django.contrib.auth.hashers import make_password

    email = response.get('email')
    first_name = response.get('given_name')
    last_name = response.get('family_name')
    picture = response.get('picture')
    username = email.split('@')[0]

    print("📩 [CREATE USER] Correo recibido:", email)

    if not usuario.objects.filter(Correo=email).exists():
        rol_default = roles.objects.get(IdRol=3)
        nuevo_usuario = usuario(
            PrimerNombre=first_name,
            PrimerApellido=last_name,
            Correo=email,  # ← CORRECTO
            NombreUsuario=username,
            Contrasena=make_password("google_login"),
            idRol=rol_default,
            imagen_perfil=picture
        )
        nuevo_usuario.save()
        print(f"✅ Usuario creado: {username}")
    else:
        print("⚠️ Usuario ya existe, no se creó otro.")

def save_custom_session(backend, user, request, *args, **kwargs):
    from appsexshop.models import usuario

    email = kwargs.get('response', {}).get('email')
    if not email:
        email = user.email

    print("📩 [SAVE SESSION] Correo:", email)

    try:
        u = usuario.objects.get(Correo=email)  # ← CORRECTO
        request.session['user_id'] = u.IdUsuario
        request.session['username'] = u.NombreUsuario
        request.session['nombre'] = f"{u.PrimerNombre} {u.PrimerApellido}"
        request.session['role'] = u.idRol.IdRol
        print("✅ Sesión iniciada para:", u.NombreUsuario)
    except usuario.DoesNotExist:
        print("❌ Usuario no encontrado para sesión")
