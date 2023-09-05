document.getElementById("sa-success").addEventListener("click", function() {
    Swal.fire({
        title: "Good job!",
        text: "You clicked the button!",
        icon: "success",
        showCancelButton: !0,
        confirmButtonColor: "#5156be",
        cancelButtonColor: "#fd625e",
    });
})