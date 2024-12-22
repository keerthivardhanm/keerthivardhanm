// Interactive features
document.addEventListener('DOMContentLoaded', () => {
  // Parallax effect for cyber background
  document.addEventListener('mousemove', (e) => {
    const cyberBg = document.querySelector('.cyber-background');
    if (cyberBg) {
      const moveX = (e.clientX * -0.01);
      const moveY = (e.clientY * -0.01);
      cyberBg.style.backgroundPosition = `${moveX}px ${moveY}px`;
    }
  });

  // Animate hobby cards on scroll
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, observerOptions);

  document.querySelectorAll('.hobby-card').forEach(card => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(20px)';
    card.style.transition = 'all 0.6s ease-out';
    observer.observe(card);
  });
});