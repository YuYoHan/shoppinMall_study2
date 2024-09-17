import styles from "./Modal.module.scss";

function Modal({ children, open, onClose }) {
    if (!open) return null;

    return (
        <div className={styles.modalOverlay}>
            <div className={styles.modalContent}>
                <button className={styles.closeButton} onClick={onClose}>X</button>
                {children}
            </div>
        </div>
    );
}

export default Modal;
