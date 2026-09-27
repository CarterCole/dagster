import {useContext} from 'react';
import {AppContext} from '../AppContext';
import {DaggyLogoDarkMode} from './DaggyLogoDarkMode';
import {DaggyLogoLightMode} from './DaggyLogoLightMode';
import styles from './css/DaggyLogo.module.css';

export const DaggyLogo = () => {
  const {branding} = useContext(AppContext);

  if (branding?.logoUrl) {
    return (
      <div className={styles.daggyContainer}>
        <img
          src={branding.logoUrl}
          style={{height: '24px', width: 'auto', display: 'block'}}
          alt="Dagster logo"
        />
      </div>
    );
  }

  return (
    <div className={styles.daggyContainer}>
      <div className={styles.daggyLightMode}>
        <DaggyLogoLightMode />
      </div>
      <div className={styles.daggyDarkMode}>
        <DaggyLogoDarkMode />
      </div>
    </div>
  );
};
