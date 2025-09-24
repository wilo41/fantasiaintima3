const carritoKey = 'carrito';
const ratingsKey = 'ratings';

// ---------- LOCALSTORAGE ----------
const obtenerCarrito = () => JSON.parse(localStorage.getItem(carritoKey) || '[]');
const guardarCarrito = (carrito) => localStorage.setItem(carritoKey, JSON.stringify(carrito));
const obtenerRatings = () => JSON.parse(localStorage.getItem(ratingsKey) || '{}');
const guardarRatings = (ratings) => localStorage.setItem(ratingsKey, JSON.stringify(ratings));

// ---------- ICONO CARRITO ----------
const actualizarIconoCarrito = () => {
  const total = obtenerCarrito().reduce((acc, item) => acc + item.cantidad, 0);
  const icono = document.getElementById('cartCount');
  if (icono) icono.textContent = total;
};

// ---------- CSRF ----------
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      cookie = cookie.trim();
      if (cookie.startsWith(name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}

// ---------- SESIÓN ----------
function verificarSesion() {
  const userInfo = document.getElementById("user-info");
  if (userInfo && userInfo.dataset.username) return true;

  Swal.fire({
    title: 'Debes iniciar sesión',
    text: 'Por favor, inicia sesión para continuar.',
    icon: 'warning',
    confirmButtonColor: '#f5365c',
    confirmButtonText: 'Iniciar Sesión'
  }).then((result) => {
    if (result.isConfirmed) window.location.href = '/login/';
  });
  return false;
}

// ---------- CARRITO ----------
function agregarAlCarrito(idProducto, cantidad = 1) {
  const card = document.querySelector(`.card[data-id='${idProducto}']`);
  if (!card) return;

  const stockDisponible = parseInt(card.getAttribute('data-cantidad') || '0');
  if (stockDisponible <= 0) return;
  if (!verificarSesion()) return;

  let carrito = obtenerCarrito();
  const index = carrito.findIndex(p => p.IdProducto == idProducto);

  if (index !== -1) {
    carrito[index].cantidad = Math.min(carrito[index].cantidad + cantidad, stockDisponible);
  } else {
    carrito.push({
      IdProducto: idProducto,
      nombre: card.getAttribute('data-nombre'),
      precio: parseFloat(card.getAttribute('data-precio')),
      cantidad: Math.min(cantidad, stockDisponible),
      imagen: card.getAttribute('data-imagen'),
      descripcion: card.getAttribute('data-descripcion'),
      stock: stockDisponible
    });
  }

  guardarCarrito(carrito);
  mostrarAlertaCarrito();
  actualizarIconoCarrito();
  agregarProductoAlCarritoBackend(idProducto, cantidad);
}

function mostrarAlertaCarrito() {
  const alerta = document.getElementById("alerta-carrito");
  if (!alerta) return;
  alerta.classList.remove("d-none");
  setTimeout(() => alerta.classList.add("d-none"), 2000);
}

async function agregarProductoAlCarritoBackend(idProducto, cantidad = 1) {
  try {
    await fetch('/api/agregar-producto-carrito/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify({ id_producto: idProducto, cantidad }),
    });
  } catch (error) {
    console.error('Error backend carrito:', error);
  }
}

// ---------- CALIFICACIONES ----------
async function guardarCalificacionBackend(idProducto, calificacion) {
  try {
    const resp = await fetch('/guardar-calificacion/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify({ id_producto: idProducto, calificacion })
    });
    return await resp.json();
  } catch (e) {
    console.error('Error backend calificación:', e);
    return { success: false };
  }
}

function pintarEstrellas(container, rating) {
  const stars = container.querySelectorAll('.star i');
  stars.forEach((star, idx) => {
    star.className = idx < rating ? 'fas fa-star text-warning' : 'far fa-star text-warning';
  });
}

function generarEstrellasVisuales(rating, reviewCount) {
  if (reviewCount === 0) return '<p class="mb-2 text-muted"><em>Sin reseñas aún</em></p>';

  const fullStars = Math.floor(rating);
  const decimal = rating - fullStars;
  const emptyStars = 5 - fullStars - (decimal > 0 ? 1 : 0);

  let html = '<div class="average-rating mb-2">';
  for (let i = 0; i < fullStars; i++) html += '<i class="fas fa-star text-warning"></i>';
  if (decimal > 0) {
    const width = decimal * 100 + '%';
    html += `<i class="fas fa-star partial text-warning" style="--partial-width:${width};"></i>`;
  }
  for (let i = 0; i < emptyStars; i++) html += '<i class="far fa-star text-warning"></i>';
  html += '</div>';
  html += `<p class="mb-2"><strong>${rating.toFixed(1)} Promedio</strong> (${reviewCount} reseñas)</p>`;
  return html;
}

// ---------- MODAL ----------
function showProductDetails(card) {
  const idProducto = card.getAttribute('data-id');
  const nombre = card.getAttribute('data-nombre');
  const precio = parseFloat(card.getAttribute('data-precio')).toLocaleString();
  const imagen = card.getAttribute('data-imagen');
  const descripcion = card.getAttribute('data-descripcion');
  const cantidad = parseInt(card.getAttribute('data-cantidad') || '0');
  const rating = parseFloat(card.getAttribute('data-rating') || '0');
  const reviewCount = parseInt(card.getAttribute('data-review-count') || '0');

  const ratings = obtenerRatings();
  const userRating = ratings[idProducto] || 0;

  const stockHtml = cantidad > 0 ? `<p>Cantidad disponible: <span id="stockQuantity">${cantidad}</span></p>` 
                                 : `<p class="text-danger">Producto sin stock</p>`;

  let estrellasHtml = '<div class="rating mb-2" id="rating-stars">';
  for (let i = 1; i <= 5; i++) {
    const iconClass = i <= userRating ? 'fas fa-star' : 'far fa-star';
    const disabled = cantidad <= 0 ? 'pointer-events: none; opacity:0.5;' : '';
    estrellasHtml += `<span class="star" data-value="${i}" style="${disabled}"><i class="${iconClass}"></i></span>`;
  }
  estrellasHtml += '</div>';

  const averageHtml = `<div id="averageRating">${generarEstrellasVisuales(rating, reviewCount)}</div>`;

  document.getElementById("productDetails").innerHTML = `
    <div class="image-container mb-3">
      <img src="${imagen}" alt="${nombre}" class="img-fluid" style="max-height:300px; object-fit:contain;">
    </div>
    <div class="product-details">
      <h3 class="product-title">${nombre}</h3>
      ${estrellasHtml}
      ${averageHtml}
      <h4 class="price">$${precio}</h4>
      <p>${descripcion}</p>
      <div class="d-flex align-items-center mb-3">
        <button class="btn btn-outline-secondary" id="decreaseQuantity">-</button>
        <input type="number" id="productQuantity" value="1" min="1" class="mx-2" style="width:60px; text-align:center;">
        <button class="btn btn-outline-secondary" id="increaseQuantity">+</button>
      </div>
      ${stockHtml}
    </div>
  `;

  const modal = document.getElementById('productModal');
  modal.setAttribute('data-id-producto', idProducto);
  document.getElementById('add-to-cart-modal').disabled = cantidad <= 0;

  // Cantidad
  const increaseBtn = document.getElementById("increaseQuantity");
  const decreaseBtn = document.getElementById("decreaseQuantity");
  const quantityInput = document.getElementById("productQuantity");

  if (increaseBtn && decreaseBtn && quantityInput) {
    increaseBtn.addEventListener("click", () => quantityInput.value = Math.min(parseInt(quantityInput.value)+1, cantidad));
    decreaseBtn.addEventListener("click", () => quantityInput.value = Math.max(parseInt(quantityInput.value)-1,1));
    quantityInput.addEventListener("input", () => {
      let val = parseInt(quantityInput.value);
      if (val>cantidad) quantityInput.value=cantidad;
      if(val<1||isNaN(val)) quantityInput.value=1;
    });
  }
}

// ---------- EVENTOS ----------
document.addEventListener('DOMContentLoaded', () => {
  actualizarIconoCarrito();

  // Click card -> modal
  document.addEventListener('click', (e) => {
    const card = e.target.closest('.card');
    if (card && !e.target.closest('.add-to-cart-btn')) {
      showProductDetails(card);
      const modalElement = document.getElementById('productModal');
      if (modalElement) new bootstrap.Modal(modalElement).show();
    }
  });

  // Agregar carrito
  document.querySelectorAll('.add-to-cart-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const card = btn.closest('.card');
      const stock = parseInt(card.getAttribute('data-cantidad') || '0');
      if (stock>0) agregarAlCarrito(card.getAttribute('data-id'),1);
      else Swal.fire({icon:'info',title:'Producto sin stock',text:'No disponible.',confirmButtonColor:'#f5365c'});
    });
  });

  // Calificación
  document.addEventListener('click', async (e) => {
    const estrella = e.target.closest('.star');
    if(!estrella) return;
    const container = estrella.closest('#rating-stars');
    if(!container) return;

    const modal = document.getElementById('productModal');
    const idProducto = modal.getAttribute('data-id-producto');
    const stock = parseInt(document.getElementById('stockQuantity')?.textContent || '0');
    if(stock<=0) return;
    if(!verificarSesion()) return;

    const value = parseInt(estrella.dataset.value);
    pintarEstrellas(container, value);

    // Guardar local
    const ratings = obtenerRatings();
    ratings[idProducto] = value;
    guardarRatings(ratings);

    // Backend
    const result = await guardarCalificacionBackend(idProducto, value);
    if(result.success){
      document.getElementById('averageRating').innerHTML = generarEstrellasVisuales(result.nuevo_promedio, result.total_reviews);
    }
  });

  // Agregar carrito modal
  const addToCartModalBtn = document.getElementById('add-to-cart-modal');
  if(addToCartModalBtn){
    addToCartModalBtn.addEventListener('click', () => {
      const modal = document.getElementById('productModal');
      const quantityInput = document.getElementById('productQuantity');
      const cantidad = quantityInput ? parseInt(quantityInput.value) : 1;
      const stock = parseInt(document.getElementById('stockQuantity').textContent || '0');
      const idProducto = modal.getAttribute('data-id-producto');
      if(stock>0 && idProducto) agregarAlCarrito(idProducto,cantidad);
      else Swal.fire({icon:'info',title:'Producto sin stock',text:'No disponible.',confirmButtonColor:'#f5365c'});
    });
  }
});

// Buscador
  const searchInput = document.getElementById('query');
searchInput.addEventListener('input', () => {
  const filtro = searchInput.value.toLowerCase().trim();
  const cards = document.querySelectorAll('#productList .card');
  let encontrados = 0;

  cards.forEach(card => {
    const nombre = card.getAttribute('data-nombre').toLowerCase();
    const visible = nombre.includes(filtro);
    card.parentElement.style.display = visible ? '' : 'none';
    if (visible) encontrados++;
  });

  const mensaje = document.getElementById('noResultsMessage');
  mensaje.classList.toggle('d-none', encontrados > 0);
    });