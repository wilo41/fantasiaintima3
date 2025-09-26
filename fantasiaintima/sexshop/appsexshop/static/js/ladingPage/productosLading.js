function getStarsHTML(rating) {
    let starsHTML = '';
    for (let i = 1; i <= 5; i++) {
        starsHTML += `<span class="star ${i <= rating ? 'active' : ''}" data-value="${i}">&#9733;</span>`;
    }
    return starsHTML;
}

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

function enviarCalificacion(id_producto, calificacion) {
    fetch('/guardar-calificacion/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `id_producto=${id_producto}&calificacion=${calificacion}`
    })
    .then(response => response.json())
    .then(data => {
    // Mostrar mensaje en pantalla
    document.getElementById("mensaje-calificacion").textContent = data.mensaje;
    document.getElementById("mensaje-calificacion").classList.remove("d-none");

    setTimeout(() => {
    document.getElementById("mensaje-calificacion").classList.add("d-none");
    }, 2000); 

    if (data.success) {
        // Actualizar el promedio mostrado
        const ratingText = document.querySelector('.rating-text');
        if (ratingText) {
            ratingText.textContent = `(${data.nuevo_promedio})`;
        }

        // Actualizar número de reviews
        const reviewSpan = document.getElementById(`review-count-${id_producto}`);
        if (reviewSpan) {
            reviewSpan.textContent = `(${data.total_reviews})`;
        }
    } else {
        console.error('Error al guardar la calificación:', data.mensaje);
    }
})
}


function actualizarReviewCount(idProducto, nuevoReviewCount) {
    const card = document.querySelector(`.card[data-id='${idProducto}']`);
    if (card) {
        card.setAttribute('data-review-count', nuevoReviewCount);
    }
}


function showProductDetails(card) {
    const idProducto = card.getAttribute('data-id');
    const nombre = card.getAttribute('data-nombre');
    const precio = parseFloat(card.getAttribute('data-precio'));
    const precioTexto = precio.toLocaleString();
    const imagen = card.getAttribute('data-imagen');
    const descripcion = card.getAttribute('data-descripcion');
    const cantidad = parseInt(card.getAttribute('data-cantidad'));
    const rating = parseFloat(card.getAttribute('data-rating')) || 4;

    const ratingStars = getStarsHTML(rating);

    document.getElementById("productDetails").innerHTML = `
        <div class="image-container mb-3 text-center">
            <img src="${imagen}" alt="${nombre}" class="img-fluid" style="max-height: 300px; object-fit: contain;">
        </div>
        <div class="product-details">
            <h3 class="product-title">${nombre}</h3>
            <div class="d-flex align-items-center mb-2">
                <div class="stars">${ratingStars}</div>
                <span class="ms-2 rating-text">(${rating.toFixed(1)})</span>
            </div>
            <h4 class="price">$${precioTexto}</h4>
            <p>${descripcion}</p>
            <p class="text-success">Envío gratis a todo el país</p>
            <div class="d-flex align-items-center mb-3">
                <button class="btn btn-outline-secondary" id="decreaseQuantity">-</button>
                <input type="number" id="productQuantity" value="1" min="1" class="mx-2" style="width: 60px; text-align: center;">
                <button class="btn btn-outline-secondary" id="increaseQuantity">+</button>
            </div>
            <p>Cantidad disponible: <span id="stockQuantity">${cantidad}</span></p>
        </div>
    `;

    // Eventos para cantidad
    const increaseBtn = document.getElementById("increaseQuantity");
    const decreaseBtn = document.getElementById("decreaseQuantity");
    const quantityInput = document.getElementById("productQuantity");

    increaseBtn.addEventListener("click", () => {
        if (parseInt(quantityInput.value) < cantidad) {
            quantityInput.value = parseInt(quantityInput.value) + 1;
        }
    });

    decreaseBtn.addEventListener("click", () => {
        if (quantityInput.value > 1) {
            quantityInput.value = parseInt(quantityInput.value) - 1;
        }
    });

    // Botón agregar al carrito
    const addToCartModalBtn = document.getElementById('add-to-cart-modal');
    if (cantidad > 0) {
        addToCartModalBtn.disabled = false;
        addToCartModalBtn.innerHTML = `Agregar al carrito <i class="fas fa-shopping-cart"></i>`;
        addToCartModalBtn.onclick = () => {
            const quantity = parseInt(quantityInput.value);
            agregarAlCarrito(idProducto, nombre, precio, quantity, imagen, descripcion);

            // mostrar alerta
            const alerta = document.getElementById("alerta-carrito");
            alerta.classList.remove("d-none");
            setTimeout(() => alerta.classList.add("d-none"), 2000);

            // cerrar modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('productModal'));
        };
    } else {
        addToCartModalBtn.disabled = true;
        addToCartModalBtn.innerHTML = `Agregar al carrito <i class="fas fa-shopping-cart"></i>`;
        addToCartModalBtn.onclick = null;
    }
}


document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.card').forEach(card => {
        card.addEventListener('click', function(e){
            const clickedInsideButton = e.target.classList.contains('add-to-cart-btn') || e.target.closest('.add-to-cart-btn');
            if (clickedInsideButton) {
                const nombre = this.getAttribute('data-nombre');
                console.log(`Agregar desde card: ${nombre}`);
                return;
            }
            showProductDetails(this);
            const modal = new bootstrap.Modal(document.getElementById('productModal'));
            modal.show();
        });
    });
});
