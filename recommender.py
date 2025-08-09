# recommender.py
import pandas as pd
from sklearn.neighbors import NearestNeighbors
from sklearn.preprocessing import MinMaxScaler, StandardScaler

def get_similar_users(target_user, all_users_df):
    # Extract features
    skills_cols = [col for col in all_users_df.columns if col.endswith('_skill')]
    prefs_cols = [col for col in all_users_df.columns if col.endswith('_pref')]
    experience_col = ['Experience_Level']

    # Scale values
    scaler_skills = MinMaxScaler()
    scaler_prefs = MinMaxScaler()
    scaler_exp = StandardScaler()

    X_skills = scaler_skills.fit_transform(all_users_df[skills_cols])
    X_prefs = scaler_prefs.fit_transform(all_users_df[prefs_cols])
    X_exp = scaler_exp.fit_transform(all_users_df[experience_col])

    # Weight features
    skills_weighted = X_skills * 1.5
    prefs_weighted = X_prefs * 2
    exp_weighted = X_exp * 1

    # Combine features
    X_combined = pd.concat([
        pd.DataFrame(skills_weighted, columns=skills_cols),
        pd.DataFrame(prefs_weighted, columns=prefs_cols),
        pd.DataFrame(exp_weighted, columns=experience_col)
    ], axis=1)

    # Not enough users to recommend anyone else
    if len(all_users_df) < 2:
        return pd.DataFrame()

    # Ask for more neighbors than needed to handle ties
    n_neighbors = min(len(all_users_df), 6)  # more than 3 to allow filtering
    knn = NearestNeighbors(n_neighbors=n_neighbors, metric='cosine')
    knn.fit(X_combined)

    _, indices = knn.kneighbors(X_combined.iloc[[target_user]])

    # Exclude the user themself
    similar_indices = [i for i in indices.flatten() if i != target_user]

    # Return up to 3 similar users
    if similar_indices:
        return all_users_df.iloc[similar_indices[:3]]
    else:
        return pd.DataFrame()