import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import axios from 'axios';
import '../styles/ProfilePage.css';
import '../styles/loader/Loader.css'; // Supondo que você tenha um loader
import SearchedUserProfile from '../components/search/SearchedUserProfile'; // Importe o novo componente

const ProfilePage = ({ currentUser }) => {
    const { habby_id } = useParams();
    const [profile, setProfile] = useState(null);
    const [history, setHistory] = useState(null);
    const [loading, setLoading] = useState(true);
    const [isEditing, setIsEditing] = useState(false);
    const [activeTab, setActiveTab] = useState('status');

    // States da Busca
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState([]);
    const [isSearchLoading, setIsSearchLoading] = useState(false);
    const searchWrapperRef = useRef(null);
    const [selectedHabbyId, setSelectedHabbyId] = useState(null);

    const isOwner = currentUser?.habby_id === habby_id;

    // Efeito para buscar dados do perfil principal (da URL)
    useEffect(() => {
        setLoading(true);
        const apiUrl = import.meta.env.VITE_API_URL;
        axios.get(`${apiUrl}/profile/${habby_id}`)
            .then(res => setProfile(res.data))
            .catch(err => {
                console.error("Erro ao buscar perfil principal:", err);
                setProfile(null);
            })
            .finally(() => setLoading(false));
    }, [habby_id]);

    // Efeito para buscar histórico do perfil principal
    useEffect(() => {
        if (activeTab === 'history' && habby_id) {
            axios.get(`http://localhost:5000/history/${habby_id}`)
                .then(res => setHistory(res.data))
                .catch(err => console.error("Erro ao buscar histórico:", err));
        }
    }, [activeTab, habby_id]);

    // Efeito para a lógica da busca com delay (debounce)
    useEffect(() => {
        if (searchQuery.trim().length < 2) {
            setSearchResults([]);
            return;
        }
        const debounceTimer = setTimeout(() => {
            setIsSearchLoading(true);
            axios.get(`http://localhost:5000/search-users?query=${searchQuery}`)
                .then(res => setSearchResults(res.data))
                .catch(() => setSearchResults([]))
                .finally(() => setIsSearchLoading(false));
        }, 300);
        return () => clearTimeout(debounceTimer);
    }, [searchQuery]);
    
    // Efeito para fechar o dropdown de resultados de busca
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (searchWrapperRef.current && !searchWrapperRef.current.contains(event.target)) {
                setSearchResults([]);
            }
        };
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, []);

    // Handlers
    const handleResultClick = (id) => {
        setSearchQuery('');
        setSearchResults([]);
        setSelectedHabbyId(id); // Define o ID para abrir o modal
    };

    const closeSearchedProfile = () => {
        setSelectedHabbyId(null); // Fecha o modal
    };
    
     const handleInputChange = (e) => {
        const { name, value } = e.target;
        setProfile({ ...profile, [name]: value });
    };

    const handleSave = async () => {
        try {
            await axios.put('http://localhost:5000/profile', profile);
            setIsEditing(false);
            alert('Perfil salvo com sucesso!');
        } catch (error) {
            alert('Falha ao salvar o perfil.');
            console.error(error);
        }
    };
    
    // Helper para renderizar campos
    const renderField = (label, name, type = 'text') => (
        <div className="form-group">
            <label>{label}</label>
            <input
                type={type}
                name={name}
                value={profile[name] || ''}
                onChange={handleInputChange}
                readOnly={!isEditing}
                className="form-input"
            />
        </div>
    );

    if (loading) return <div className="loader"></div>;

    return (
        <div className="profile-page-wrapper">
            <div className="profile-search-container">
                <h2>Buscar Outro Usuário</h2>
                <div className="search-wrapper" ref={searchWrapperRef}>
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Buscar por Nick ou Habby ID..."
                        className="search-input"
                        autoComplete="off"
                    />
                    {isSearchLoading && <div className="loader-small"></div>}
                    {searchResults.length > 0 && (
                        <div className="search-results-dropdown">
                            {searchResults.map(user => (
                                <div 
                                    key={user.habby_id} 
                                    className="search-result-item"
                                    onClick={() => handleResultClick(user.habby_id)}
                                >
                                    <p className="result-nick">{user.nick}</p>
                                    <p className="result-habby-id">{user.habby_id}</p>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Renderiza o modal se um usuário foi selecionado */}
            {selectedHabbyId && (
                <SearchedUserProfile 
                    habbyId={selectedHabbyId} 
                    onClose={closeSearchedProfile} 
                />
            )}

            {/* Perfil Principal */}
            {!profile ? (
                <div className="profile-container">Perfil não encontrado.</div>
            ) : (
                <>
                    {/* ... O JSX do seu perfil principal (profile-header, profile-tabs, etc) permanece aqui ... */}
                    <div className="profile-header">
                         <img src={profile.profile_pic_url || 'https://via.placeholder.com/150'} alt="Perfil" className="profile-picture" />
                         <div className="profile-titles">
                             <h1>{profile.nick || 'Nome não definido'}</h1>
                             <p>ID Habby: {profile.habby_id}</p>
                         </div>
                         {isOwner && (
                    <div className="profile-actions">
                        {isEditing ? (
                            <>
                                <button onClick={handleSave} className="btn btn-save">Salvar</button>
                                <button onClick={() => setIsEditing(false)} className="btn btn-cancel">Cancelar</button>
                            </>
                        ) : (
                            <button onClick={() => setIsEditing(true)} className="btn btn-edit">Editar Perfil</button>
                        )}
                    </div>
                )}
                     </div>
                     <div className="profile-tabs">
                         <button onClick={() => setActiveTab('status')} className={activeTab === 'status' ? 'active' : ''}>Status</button>
                         <button onClick={() => setActiveTab('history')} className={activeTab === 'history' ? 'active' : ''}>Histórico</button>
                     </div>
                     {activeTab === 'status' && (
                <div className="profile-body">
                    <div className="status-section">
                        <h2>Dados Gerais</h2>
                        {renderField('Link da Foto de Perfil', 'profile_pic_url')}
                        {renderField('Nick', 'nick')}
                        {renderField('ATK Total', 'atk', 'number')}
                        {renderField('HP Total', 'hp', 'number')}
                    </div>
                    
                    <div className="status-grid">
                        <div className="status-section">
                            <h3>Status do Sobrevivente</h3>
                            {renderField('ATQ Base', 'survivor_base_atk', 'number')}
                            {renderField('HP Base', 'survivor_base_hp', 'number')}
                            {renderField('Bônus ATQ', 'survivor_bonus_atk', 'number')}
                            {renderField('Bônus HP', 'survivor_bonus_hp', 'number')}
                            {renderField('ATQ Final', 'survivor_final_atk', 'number')}
                            {renderField('HP Final', 'survivor_final_hp', 'number')}
                            {renderField('Taxa Crit.', 'survivor_crit_rate', 'number')}
                            {renderField('Dano Crit.', 'survivor_crit_damage', 'number')}
                            {renderField('Dano de Habilidade', 'survivor_skill_damage', 'number')}
                            {renderField('Boost Dano Escudo', 'survivor_shield_boost', 'number')}
                            {renderField('Envenenamento', 'survivor_poison_targets', 'number')}
                            {renderField('Enfraquecimento', 'survivor_weak_targets', 'number')}
                            {renderField('Congelamento', 'survivor_frozen_targets', 'number')}
                        </div>
                        <div className="status-section">
                            <h3>Status do Bichinho</h3>
                            {renderField('ATQ Base', 'pet_base_atk', 'number')}
                            {renderField('HP Base', 'pet_base_hp', 'number')}
                            {renderField('Dano Crit.', 'pet_crit_damage', 'number')}
                            {renderField('Dano Habilidade.', 'pet_skill_damage', 'number')}
                        </div>
                        <div className="status-section">
                            <h3>Coletáveis</h3>
                            {renderField('ATQ Final', 'collect_final_atk', 'number')}
                            {renderField('HP Final', 'collect_final_hp', 'number')}
                            {renderField('Taxa Crit.', 'collect_crit_rate', 'number')}
                            {renderField('Dano Crit.', 'collect_crit_damage', 'number')}
                            {renderField('Dano de Habilidade', 'collect_skill_damage', 'number')}
                            {renderField('Envenenamento', 'collect_poison_targets', 'number')}
                            {renderField('Enfraquecimento', 'collect_weak_targets', 'number')}
                            {renderField('Congelamento', 'collect_frozen_targets', 'number')}                        
                        </div>
                    </div>
                </div>
            )}
            
            {activeTab === 'history' && (
                <div className="history-tab">
                    <h2>Histórico de Participação (Última Temporada)</h2>
                    {history ? (
                        <div className="history-card">
                            <p><strong>Posição no Ranking de Acesso:</strong> {history.position || 'N/A'}º</p>
                            <p><strong>Pontuação (Fase de Acesso):</strong> {history.fase_acesso || 'N/A'}</p>
                            <p><strong>Evolução vs Temporada Anterior:</strong> {history.evolution || '-'}</p>
                        </div>
                    ) : (
                       <p>Nenhum histórico encontrado para este membro.</p>
                    )}
                </div>
            )}
                </>
            )}
        </div>
    );
};

export default ProfilePage;




