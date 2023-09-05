const swiper = new Swiper(".swiper", {
    // Optional parameters
    direction: "horizontal",

    autoplay: {
      delay: 4000,
    },
    autoHeight: true,

    slidesPerView: 5,
    spaceBetween: 10,
    // Responsive breakpoints
    breakpoints: {
      // when window width is >= 320px
      320: {
        slidesPerView: 1,
        spaceBetween: 20,
      },
      // when window width is >= 480px
      480: {
        slidesPerView: 1,
        spaceBetween: 30,
      },
      // when window width is >= 640px
      640: {
        slidesPerView: 1,
        spaceBetween: 40,
      },
      1024: {
        slidesPerView: 2,
        spaceBetween: 40,
      },
    },
  });